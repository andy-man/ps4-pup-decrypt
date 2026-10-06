#include "ps4.h"
#include "defines.h"
#include "status.h"

static int write_all(int fd, const char *buffer, size_t length)
{
  size_t written = 0;

  while (written < length)
  {
    ssize_t result = write(fd, buffer + written, length - written);
    if (result <= 0)
    {
      return -1;
    }

    written += (size_t)result;
  }

  return 0;
}

int status_write(const char *message)
{
  if (message == NULL)
  {
    return -1;
  }

  int fd = open(STATUSPATH, O_WRONLY | O_CREAT | O_TRUNC, 0777);
  if (fd < 0)
  {
    return -1;
  }

  int result = write_all(fd, message, strlen(message));
  int close_result = close(fd);

  if (result != 0 || close_result != 0)
  {
    return -1;
  }

  return 0;
}

int status_touch(const char *path)
{
  if (path == NULL)
  {
    return -1;
  }

  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0777);
  if (fd < 0)
  {
    return -1;
  }

  return close(fd) == 0 ? 0 : -1;
}
