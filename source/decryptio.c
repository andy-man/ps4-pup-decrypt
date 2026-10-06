#include "ps4.h"

#include <assert.h>

#include "decryptio.h"
#include "defines.h"
#include "debug.h"

#define chunksize 2097152
#define SSIZET_FMT "%zd"

ssize_t readbytes(const decrypt_state *state, size_t offset, size_t bytes, void *buffer, size_t buffersize)
{
  if (bytes > buffersize)
  {
    printf_notification("ReadBytes failed! - Error: Buffer is too small!\n");
    return -1;
  }

  ssize_t result = -1;

  if (offset != 0)
  {
    switch (offset)
    {
      case DIO_RESET:
        result = lseek(state->input_file, 0, SEEK_SET);
        break;
      case DIO_BASEOFFSET:
        result = lseek(state->input_file, state->input_base_offset, SEEK_SET);
        break;
      default:
        result = lseek(state->input_file, state->input_base_offset + offset, SEEK_SET);
        break;
    }

    if (result == -1)
    {
      int errcode = errno;
      printf_notification("ReadBytes seek_set failed! - Error: %d (%s)\n", errcode, strerror(errcode));
      return -1;
    }
  }

  size_t rchunksize = (bytes >= chunksize) ? chunksize : bytes;
  size_t bytesread = 0;
  size_t bytesremaining = bytes;

  while (bytesremaining > 0)
  {
    result = read(state->input_file,
                  (uint8_t *)buffer + bytesread,
                  (bytesremaining >= rchunksize) ? rchunksize : bytesremaining);

    if (result < 1)
    {
      break;
    }

    bytesread += result;
    bytesremaining -= result;
  }

  if ((result == -1) || (bytesread != bytes))
  {
    int errcode = errno;
    printf_notification("Read failed; Read " SSIZET_FMT " of " SSIZET_FMT " bytes - Error: %d (%s)\n",
                        bytesread, bytes, errcode, strerror(errcode));
    return -1;
  }

  return bytesread;
}

ssize_t writebytes(const decrypt_state *state, size_t offset, size_t bytes, void *buffer, size_t buffersize)
{
  if (bytes > buffersize)
  {
    printf_notification("WriteBytes failed! - Error: Buffer is too small!\n");
    return -1;
  }

  ssize_t result = -1;

  if (offset != 0)
  {
    switch (offset)
    {
      case DIO_RESET:
        result = lseek(state->output_file, 0, SEEK_SET);
        break;
      case DIO_BASEOFFSET:
        result = lseek(state->output_file, state->output_base_offset, SEEK_SET);
        break;
      default:
        result = lseek(state->output_file, state->output_base_offset + offset, SEEK_SET);
        break;
    }

    if (result == -1)
    {
      int errcode = errno;
      printf_notification("WriteBytes seek_set failed! - Error: %d (%s)\n", errcode, strerror(errcode));
      return -1;
    }
  }

  size_t wchunksize = (bytes >= chunksize) ? chunksize : bytes;
  size_t byteswritten = 0;
  size_t bytesremaining = bytes;

  while (bytesremaining > 0)
  {
    result = write(state->output_file,
                   (uint8_t *)buffer + byteswritten,
                   (bytesremaining >= wchunksize) ? wchunksize : bytesremaining);

    if (result < 1)
    {
      break;
    }

    byteswritten += result;
    bytesremaining -= result;
  }

  if ((result == -1) || (byteswritten != bytes))
  {
    int errcode = errno;
    printf_notification("Write failed; Wrote " SSIZET_FMT " of " SSIZET_FMT " bytes - Error: %d (%s)\n",
                        byteswritten, bytes, errcode, strerror(errcode));
    return -1;
  }

  return byteswritten;
}
