#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "threads/malloc.h"

// Lock for file system operations
static struct lock filesys_lock;

// File descriptor structure
struct file_descriptor
{
  int fd;
  struct file *file;
  struct list_elem elem;
};

static void syscall_handler (struct intr_frame *);
static void validate_user_ptr (const void *ptr);
static void validate_user_buffer (const void *buffer, unsigned size);
static void validate_user_string (const char *str);
static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);

// System call implementations 
static void sys_halt (void);
static void sys_exit (int status);
static pid_t sys_exec (const char *cmd_line);
static int sys_wait (pid_t pid);
static bool sys_create (const char *file, unsigned initial_size);
static bool sys_remove (const char *file);
static int sys_open (const char *file);
static int sys_filesize (int fd);
static int sys_read (int fd, void *buffer, unsigned size);
static int sys_write (int fd, const void *buffer, unsigned size);
static void sys_seek (int fd, unsigned position);
static unsigned sys_tell (int fd);
static void sys_close (int fd);

// File descriptor helper functions
static struct file_descriptor *get_file_descriptor (int fd);
static int allocate_fd (void);

void
syscall_init (void) 
{
  lock_init (&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  // Validate stack pointer
  validate_user_ptr (f->esp);
  
  int syscall_number = *(int *)(f->esp);
  int *args = (int *)(f->esp) + 1;

  // Validate all argument pointers */
  switch (syscall_number)
    {
    case SYS_HALT:
      sys_halt ();
      break;
      
    case SYS_EXIT:
      validate_user_ptr (args);
      sys_exit (args[0]);
      break;
      
    case SYS_EXEC:
      validate_user_ptr (args);
      validate_user_string ((const char *)args[0]);
      f->eax = sys_exec ((const char *)args[0]);
      break;
      
    case SYS_WAIT:
      validate_user_ptr (args);
      f->eax = sys_wait (args[0]);
      break;
      
    case SYS_CREATE:
      validate_user_ptr (args);
      validate_user_ptr (args + 1);
      validate_user_string ((const char *)args[0]);
      f->eax = sys_create ((const char *)args[0], args[1]);
      break;
      
    case SYS_REMOVE:
      validate_user_ptr (args);
      validate_user_string ((const char *)args[0]);
      f->eax = sys_remove ((const char *)args[0]);
      break;
      
    case SYS_OPEN:
      validate_user_ptr (args);
      validate_user_string ((const char *)args[0]);
      f->eax = sys_open ((const char *)args[0]);
      break;
      
    case SYS_FILESIZE:
      validate_user_ptr (args);
      f->eax = sys_filesize (args[0]);
      break;
      
    case SYS_READ:
      validate_user_ptr (args);
      validate_user_ptr (args + 1);
      validate_user_ptr (args + 2);
      validate_user_buffer ((void *)args[1], args[2]);
      f->eax = sys_read (args[0], (void *)args[1], args[2]);
      break;
      
    case SYS_WRITE:
      validate_user_ptr (args);
      validate_user_ptr (args + 1);
      validate_user_ptr (args + 2);
      validate_user_buffer ((const void *)args[1], args[2]);
      f->eax = sys_write (args[0], (const void *)args[1], args[2]);
      break;
      
    case SYS_SEEK:
      validate_user_ptr (args);
      validate_user_ptr (args + 1);
      sys_seek (args[0], args[1]);
      break;
      
    case SYS_TELL:
      validate_user_ptr (args);
      f->eax = sys_tell (args[0]);
      break;
      
    case SYS_CLOSE:
      validate_user_ptr (args);
      sys_close (args[0]);
      break;
      
    default:
      printf ("Unknown system call: %d\n", syscall_number);
      sys_exit (-1);
      break;
    }
}

// Validates a user pointer 
static void
validate_user_ptr (const void *ptr)
{
  if (ptr == NULL || !is_user_vaddr (ptr) || 
      get_user ((const uint8_t *)ptr) == -1)
    {
      sys_exit (-1);
    }
}

// Validates a user buffer
static void
validate_user_buffer (const void *buffer, unsigned size)
{
  unsigned i;
  const uint8_t *buf = (const uint8_t *)buffer;
  
  for (i = 0; i < size; i++)
    {
      validate_user_ptr (buf + i);
    }
}

// Validates a user string 
static void
validate_user_string (const char *str)
{
  validate_user_ptr (str);
  
  while (get_user ((const uint8_t *)str) != 0)
    {
      str++;
      validate_user_ptr (str);
    }
}

// Reads a byte at user virtual address
static int
get_user (const uint8_t *uaddr)
{
  if (!is_user_vaddr (uaddr))
    return -1;
    
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

// Writes BYTE to user address UDST.
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  if (!is_user_vaddr (udst))
    return false;
    
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

// System call implementations
static void
sys_halt (void)
{
  shutdown_power_off ();
}

static void
sys_exit (int status)
{
  struct thread *cur = thread_current ();
  cur->exit_status = status;
  printf ("%s: exit(%d)\n", cur->name, status);
  thread_exit ();
}

static pid_t
sys_exec (const char *cmd_line)
{
  lock_acquire (&filesys_lock);
  pid_t pid = process_execute (cmd_line);
  lock_release (&filesys_lock);
  return pid;
}

static int
sys_wait (pid_t pid)
{
  return process_wait (pid);
}

static bool
sys_create (const char *file, unsigned initial_size)
{
  if (file == NULL || strlen (file) == 0)
    sys_exit (-1);
    
  lock_acquire (&filesys_lock);
  bool success = filesys_create (file, initial_size);
  lock_release (&filesys_lock);
  return success;
}

static bool
sys_remove (const char *file)
{
  if (file == NULL)
    sys_exit (-1);
    
  lock_acquire (&filesys_lock);
  bool success = filesys_remove (file);
  lock_release (&filesys_lock);
  return success;
}

static int
sys_open (const char *file)
{
  if (file == NULL || strlen (file) == 0)
    return -1;
    
  lock_acquire (&filesys_lock);
  struct file *f = filesys_open (file);
  lock_release (&filesys_lock);
  
  if (f == NULL)
    return -1;
    
  struct file_descriptor *fd_struct = malloc (sizeof (struct file_descriptor));
  if (fd_struct == NULL)
    {
      lock_acquire (&filesys_lock);
      file_close (f);
      lock_release (&filesys_lock);
      return -1;
    }
    
  fd_struct->fd = allocate_fd ();
  fd_struct->file = f;
  
  struct thread *cur = thread_current ();
  list_push_back (&cur->file_descriptors, &fd_struct->elem);
  
  return fd_struct->fd;
}

static int
sys_filesize (int fd)
{
  struct file_descriptor *fd_struct = get_file_descriptor (fd);
  if (fd_struct == NULL)
    return -1;
    
  lock_acquire (&filesys_lock);
  int size = file_length (fd_struct->file);
  lock_release (&filesys_lock);
  
  return size;
}

static int
sys_read (int fd, void *buffer, unsigned size)
{
  if (size == 0)
    return 0;
    
  if (fd == 0) 
    {
      unsigned i;
      uint8_t *buf = (uint8_t *)buffer;
      for (i = 0; i < size; i++)
        {
          buf[i] = input_getc ();
        }
      return size;
    }
    
  struct file_descriptor *fd_struct = get_file_descriptor (fd);
  if (fd_struct == NULL)
    return -1;
    
  lock_acquire (&filesys_lock);
  int bytes_read = file_read (fd_struct->file, buffer, size);
  lock_release (&filesys_lock);
  
  return bytes_read;
}

static int
sys_write (int fd, const void *buffer, unsigned size)
{
  if (size == 0)
    return 0;

  if (fd == 1) 
    {
      putbuf (buffer, size);
      return size;
    }
    
  struct file_descriptor *fd_struct = get_file_descriptor (fd);
  if (fd_struct == NULL)
    return -1;
    
  lock_acquire (&filesys_lock);
  int bytes_written = file_write (fd_struct->file, buffer, size);
  lock_release (&filesys_lock);
  
  return bytes_written;
}

static void
sys_seek (int fd, unsigned position)
{
  struct file_descriptor *fd_struct = get_file_descriptor (fd);
  if (fd_struct == NULL)
    return;
    
  lock_acquire (&filesys_lock);
  file_seek (fd_struct->file, position);
  lock_release (&filesys_lock);
}

static unsigned
sys_tell (int fd)
{
  struct file_descriptor *fd_struct = get_file_descriptor (fd);
  if (fd_struct == NULL)
    return 0;
    
  lock_acquire (&filesys_lock);
  unsigned position = file_tell (fd_struct->file);
  lock_release (&filesys_lock);
  
  return position;
}

static void
sys_close (int fd)
{
  struct file_descriptor *fd_struct = get_file_descriptor (fd);
  if (fd_struct == NULL)
    return;
    
  lock_acquire (&filesys_lock);
  file_close (fd_struct->file);
  lock_release (&filesys_lock);
  
  list_remove (&fd_struct->elem);
  free (fd_struct);
}


static struct file_descriptor *
get_file_descriptor (int fd)
{
  struct thread *cur = thread_current ();
  struct list_elem *e;
  
  for (e = list_begin (&cur->file_descriptors);
       e != list_end (&cur->file_descriptors);
       e = list_next (e))
    {
      struct file_descriptor *fd_struct = list_entry (e, struct file_descriptor, elem);
      if (fd_struct->fd == fd)
        return fd_struct;
    }
    
  return NULL;
}

static int
allocate_fd (void)
{
  static int next_fd = 2; 
  return next_fd++;
}
void
syscall_close_all_files (void)
{
  struct thread *cur = thread_current ();
  struct list_elem *e = list_begin (&cur->file_descriptors);
  
  while (e != list_end (&cur->file_descriptors))
    {
      struct file_descriptor *fd_struct = list_entry (e, struct file_descriptor, elem);
      e = list_next (e);
      
      lock_acquire (&filesys_lock);
      file_close (fd_struct->file);
      lock_release (&filesys_lock);
      
      list_remove (&fd_struct->elem);
      free (fd_struct);
    }
}