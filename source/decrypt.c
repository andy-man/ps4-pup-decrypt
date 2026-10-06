#include "ps4.h"
#include "pup.h"
#include "bls.h"
#include "decryptio.h"
#include "encryptsrv.h"
#include "defines.h"
#include "debug.h"
#include "status.h"

static void status_entry(const decrypt_state *state, const char *status, const char *stage)
{
  if (state == NULL || state->notifystr == NULL)
  {
    return;
  }

  sprintf(state->notifystr,
          "%s\nentry=%s\nentry_number=%d/%d\nstage=%s\n",
          status,
          state->entryname != NULL ? state->entryname : "unknown",
          state->entryid,
          state->totalentries,
          stage != NULL ? stage : "unknown");
  status_write(state->notifystr);
}

static void status_error(const decrypt_state *state, const char *stage,
                         int segment, int block, int error_code)
{
  if (state == NULL || state->notifystr == NULL)
  {
    return;
  }

  sprintf(state->notifystr,
          "ERROR\nentry=%s\nentry_number=%d/%d\nstage=%s\nsegment=%d\nblock=%d\nerror=%d\n",
          state->entryname != NULL ? state->entryname : "unknown",
          state->entryid,
          state->totalentries,
          stage != NULL ? stage : "unknown",
          segment,
          block,
          error_code);
  status_write(state->notifystr);
}

static void status_block_progress(const decrypt_state *state, int segment,
                                  int block, int block_count)
{
  if (state == NULL || state->notifystr == NULL || block_count <= 0)
  {
    return;
  }

  uint32_t percentage = (uint32_t)(((uint64_t)(block + 1) * 100ULL) /
                                   (uint64_t)block_count);

  sprintf(state->notifystr,
          "RUNNING\nentry=%s\nentry_number=%d/%d\nstage=decrypt_block\nsegment=%d\nblock=%d/%d\npercent=%d\n",
          state->entryname != NULL ? state->entryname : "unknown",
          state->entryid,
          state->totalentries,
          segment,
          block + 1,
          block_count,
          percentage);
  status_write(state->notifystr);

  sprintf(state->notifystr,
          "%s (%d/%d): segment %d, %d%%",
          state->entryname != NULL ? state->entryname : "PUP",
          state->entryid,
          state->totalentries,
          segment,
          percentage);
  printf_notification(state->notifystr);
}

int verify_segment(const decrypt_state *state, int index, pup_segment *segment, int additional)
{
  int result = -1;
  uint8_t *buffer = NULL;

  buffer = memalign(0x4000, segment->compressed_size);
  if (buffer == NULL)
  {
    printf_notification("Failed to allocate verification buffer for segment #%d!\n", index);
    status_error(state, "allocate_verify_segment", index, -1, 0);
    goto end;
  }

  ssize_t bytesread = readbytes(state, segment->offset, segment->compressed_size,
                                buffer, segment->compressed_size);
  if (bytesread != segment->compressed_size)
  {
    int errcode = errno;
    printf_notification("Failed to read segment #%d for verification!\n", index);
    status_error(state, "read_verify_segment", index, -1, errcode);
    result = -1;
    goto end;
  }

  result = encsrv_verify_segment(state->device_fd, index, buffer,
                                 segment->compressed_size, additional);
  if (result != 0)
  {
    int errcode = errno;
    printf_notification("Failed to verify segment #%d! %d\n", index, errcode);
    status_error(state, "verify_segment", index, -1, errcode);
    goto end;
  }

  result = 0;

end:
  if (buffer != NULL)
  {
    free(buffer);
  }

  return result;
}

int verify_segments(const decrypt_state *state, pup_segment *segments, int segment_count)
{
  int result = 0;

  for (int i = 0; i < segment_count; i++)
  {
    pup_segment *segment = &segments[i];
    if ((segment->flags & 0xF0000000) == 0xE0000000)
    {
      printf_notification("Verifying segment #%d (%d)... [1]\n", i, segment->flags >> 20);
      result = verify_segment(state, i, segment, 1);
      if (result != 0)
      {
        goto end;
      }
    }
  }

  for (int i = 0; i < segment_count; i++)
  {
    pup_segment *segment = &segments[i];
    if ((segment->flags & 0xF0000000) == 0xF0000000)
    {
      printf_notification("Verifying segment #%d (%d)... [0]\n", i, segment->flags >> 20);
      result = verify_segment(state, i, segment, 0);
      if (result != 0)
      {
        goto end;
      }
    }
  }

end:
  return result;
}

int decrypt_segment(const decrypt_state *state, uint16_t index, pup_segment *segment)
{
  int result = -1;
  uint8_t *buffer = NULL;

  buffer = memalign(0x4000, segment->compressed_size);
  if (buffer == NULL)
  {
    printf_notification("Failed to allocate buffer for segment #%d!\n", index);
    status_error(state, "allocate_segment", index, -1, 0);
    goto end;
  }

  int is_compressed = (segment->flags & 8) != 0 ? 1 : 0;

  size_t remaining_size = segment->compressed_size;
  if (is_compressed == 1)
  {
    remaining_size &= ~0xFull;
  }

  if (remaining_size > 0)
  {
    size_t padding_size = segment->compressed_size & 0xF;
    size_t encrypted_size = remaining_size;

    if (segment->compressed_size < remaining_size)
    {
      encrypted_size = segment->compressed_size;
    }

    ssize_t bytesread = readbytes(state, segment->offset, encrypted_size,
                                  buffer, segment->compressed_size);
    if (bytesread != encrypted_size)
    {
      int errcode = errno;
      printf_notification("Failed to read segment #%d!\n", index);
      status_error(state, "read_segment", index, -1, errcode);
      result = -1;
      goto end;
    }

    result = encsrv_decrypt_segment(state->device_fd, index, buffer, encrypted_size);
    if (result != 0)
    {
      int errcode = errno;
      printf_notification("Failed to decrypt segment #%d! - Error: %d (%s)\n",
                          index, errcode, strerror(errcode));
      status_error(state, "decrypt_segment", index, -1, errcode);
      goto end;
    }

    size_t unencrypted_size = remaining_size - padding_size;
    if (is_compressed == 0 || encrypted_size != remaining_size)
    {
      unencrypted_size = encrypted_size;
    }

    ssize_t byteswritten = writebytes(state, segment->offset, unencrypted_size,
                                      buffer, segment->compressed_size);
    if (byteswritten != unencrypted_size)
    {
      int errcode = errno;
      printf_notification("Failed to write segment #%d!\n", index);
      status_error(state, "write_segment", index, -1, errcode);
      result = -1;
      goto end;
    }
  }

  result = 0;

end:
  if (buffer != NULL)
  {
    free(buffer);
  }

  return result;
}

int decrypt_segment_blocks(const decrypt_state *state, uint16_t index, pup_segment *segment,
                           uint16_t table_index, pup_segment *table_segment)
{
  int result = -1;
  uint8_t *table_buffer = NULL;
  uint8_t *block_buffer = NULL;

  size_t table_length = table_segment->compressed_size;
  table_buffer = memalign(0x4000, table_length);
  if (table_buffer == NULL)
  {
    printf_notification("Failed to allocate table buffer for segment #%d!\n", index);
    status_error(state, "allocate_table", index, -1, 0);
    goto end;
  }

  ssize_t bytesread = readbytes(state, table_segment->offset, table_length,
                                table_buffer, table_length);
  if (bytesread != table_length)
  {
    int errcode = errno;
    printf_notification("Failed to read table for segment #%d!\n", index);
    status_error(state, "read_table", index, -1, errcode);
    result = -1;
    goto end;
  }

  printf_notification("Decrypting table #%d for segment #%d\n", table_index, index);
  result = encsrv_decrypt_segment(state->device_fd, table_index,
                                  table_buffer, table_length);
  if (result != 0)
  {
    int errcode = errno;
    printf_notification("Failed to decrypt table for segment #%d! Error: %d (%s)\n",
                        index, errcode, strerror(errcode));
    status_error(state, "decrypt_table", index, -1, errcode);
    goto end;
  }

  int is_compressed = (segment->flags & 8) != 0 ? 1 : 0;

  size_t block_size = 1 << (((segment->flags & 0xF000) >> 12) + 12);
  size_t block_count = (block_size + segment->uncompressed_size - 1) / block_size;

  size_t tail_size = segment->uncompressed_size % block_size;
  if (tail_size == 0)
  {
    tail_size = block_size;
  }

  pup_block_info *block_info = NULL;
  if (is_compressed == 1)
  {
    size_t valid_table_length = block_count * (32 + sizeof(pup_block_info));
    if (valid_table_length != table_length)
    {
      printf_notification("Strange segment #%d table: %llu vs %llu\n",
                          index, valid_table_length, table_length);
    }
    block_info = (pup_block_info *)&table_buffer[32 * block_count];
  }

  block_buffer = memalign(0x4000, block_size);
  if (block_buffer == NULL)
  {
    printf_notification("Failed to allocate block buffer for segment #%d!\n", index);
    status_error(state, "allocate_block", index, -1, 0);
    result = -1;
    goto end;
  }

  printf_notification("Decrypting %d blocks for segment #%d...\n", block_count, index);
  status_entry(state, "RUNNING", "decrypt_blocks");

  int Seeked = 0;
  GetElapsed(0);

  size_t remaining_size = segment->compressed_size;
  int last_index = block_count - 1;

  for (int i = 0; i < block_count; i++)
  {
    size_t read_size;
    ssize_t block_offset = 0;

    if (is_compressed == 1)
    {
      pup_block_info *tblock_info = &block_info[i];
      uint32_t unpadded_size = (tblock_info->size & ~0xFu) - (tblock_info->size & 0xFu);

      read_size = block_size;
      if (unpadded_size != block_size)
      {
        read_size = tblock_info->size;
        if (i != last_index || tail_size != tblock_info->size)
        {
          read_size &= ~0xFu;
        }
      }

      if (block_info->offset != 0)
      {
        block_offset = tblock_info->offset;
      }
    }
    else
    {
      read_size = remaining_size;
      if (block_size < read_size)
      {
        read_size = block_size;
      }
    }

    size_t SeekTo = DIO_NOSEEK;
    if (Seeked == 0)
    {
      SeekTo = (block_offset != 0) ? (segment->offset + block_offset) : segment->offset;
    }
    else
    {
      SeekTo = (Seeked != 0) ? DIO_NOSEEK : segment->offset;
    }

    bytesread = readbytes(state, SeekTo, read_size, block_buffer, block_size);
    if (bytesread != read_size)
    {
      int errcode = errno;
      printf_notification("Failed to read block %d for segment #%d! %d\n",
                          i, index, bytesread);
      status_error(state, "read_block", index, i, errcode);
      result = -1;
      goto end;
    }

    result = encsrv_decrypt_segment_block(state->device_fd, index, i,
                                          block_buffer, read_size,
                                          table_buffer, table_length);
    if (result != 0)
    {
      int errcode = errno;
      printf_notification("Failed to decrypt block %d for segment #%d! Error: %d (%s)\n",
                          i, index, errcode, strerror(errcode));
      status_error(state, "decrypt_block", index, i, errcode);
      goto end;
    }

    ssize_t byteswritten = writebytes(state, SeekTo, read_size,
                                      block_buffer, block_size);
    if (byteswritten != read_size)
    {
      int errcode = errno;
      printf_notification("Failed to write block %d for segment #%d!\n", i, index);
      status_error(state, "write_block", index, i, errcode);
      result = -1;
      goto end;
    }

    Seeked = 1;
    remaining_size -= read_size;

    if ((block_count > 50) && (GetElapsed(15) == 1))
    {
      status_block_progress(state, index, i, block_count);
    }
  }

  result = 0;

end:
  if (block_buffer != NULL)
  {
    free(block_buffer);
  }

  if (table_buffer != NULL)
  {
    free(table_buffer);
  }

  return result;
}

int find_table_segment(int index, pup_segment *segments, int segment_count,
                       int *table_index)
{
  if (((index | 0x100) & 0xF00) == 0xF00)
  {
    printf_notification("Can't do table for segment #%d\n", index);
    *table_index = -1;
    return -1;
  }

  for (int i = 0; i < segment_count; i++)
  {
    if (segments[i].flags & 1)
    {
      uint32_t id = segments[i].flags >> 20;
      if (id == index)
      {
        *table_index = i;
        return 0;
      }
    }
  }

  return -2;
}

int decrypt_pup_data(const decrypt_state *state)
{
  int result = -1;
  ssize_t bytesread;
  uint8_t *header_data = NULL;

  status_entry(state, "RUNNING", "read_pup_header");

  pup_file_header file_header;
  bytesread = readbytes(state, DIO_BASEOFFSET, sizeof(file_header),
                        &file_header, sizeof(file_header));
  if (bytesread != sizeof(file_header))
  {
    int errcode = errno;
    printf_notification("Failed to read PUP entry header!\n");
    status_error(state, "read_pup_header", -1, -1, errcode);
    goto end;
  }

  if (file_header.magic != 0x1D3D154F)
  {
    printf_notification("PUP header magic is invalid!\n");
    status_error(state, "validate_pup_magic", -1, -1, 0);
    goto end;
  }

  size_t header_size = (size_t)file_header.unknown_0C + (size_t)file_header.unknown_0E;
  if (header_size < sizeof(file_header))
  {
    printf_notification("PUP header size is invalid!\n");
    status_error(state, "validate_pup_header_size", -1, -1, 0);
    goto end;
  }

  header_data = memalign(0x4000, header_size);
  if (header_data == NULL)
  {
    printf_notification("Failed to allocate PUP header buffer!\n");
    status_error(state, "allocate_pup_header", -1, -1, 0);
    goto end;
  }

  memcpy(header_data, &file_header, sizeof(file_header));

  size_t tsize = header_size - sizeof(file_header);
  bytesread = readbytes(state, DIO_NOSEEK, tsize,
                        &header_data[sizeof(file_header)], header_size);
  if (bytesread != tsize)
  {
    int errcode = errno;
    printf_notification("Failed to read PUP entry header!\n");
    status_error(state, "read_pup_header_body", -1, -1, errcode);
    goto end;
  }

  if ((file_header.flags & 1) == 0)
  {
    status_entry(state, "RUNNING", "decrypt_header");
    printf_notification("Decrypting header...\n");
    result = encsrv_decrypt_header(state->device_fd, header_data,
                                   header_size, state->pup_type);
    if (result != 0)
    {
      int errcode = errno;
      printf_notification("Failed to decrypt header! Error: %d (%s)\n",
                          errcode, strerror(errcode));
      status_error(state, "decrypt_header", -1, -1, errcode);
      goto end;
    }
  }
  else
  {
    printf_notification("Can't decrypt network pup!\n");
    status_error(state, "network_pup_not_supported", -1, -1, 0);
    goto end;
  }

  pup_header *header = (pup_header *)&header_data[0];
  pup_segment *segments = (pup_segment *)&header_data[0x20];

  size_t required_header_size = 0x20 + ((size_t)header->segment_count * sizeof(pup_segment));
  if (required_header_size > header_size)
  {
    printf_notification("PUP segment table extends beyond the decrypted header!\n");
    status_error(state, "validate_segment_table", -1, -1, 0);
    goto end;
  }

  ssize_t byteswritten = writebytes(state, DIO_BASEOFFSET, header_size,
                                    header_data, header_size);
  if (byteswritten != header_size)
  {
    int errcode = errno;
    printf_notification("Failed to write PUP entry header!\n");
    status_error(state, "write_pup_header", -1, -1, errcode);
    goto end;
  }

  status_entry(state, "RUNNING", "verify_segments");
  printf_notification("Verifying segments...\n");
  result = verify_segments(state, segments, header->segment_count);
  if (result != 0)
  {
    printf_notification("Failed to verify segments!\n");
    goto end;
  }

  printf_notification("Decrypting %d segments...\n", header->segment_count);
  for (int i = 0; i < header->segment_count; i++)
  {
    pup_segment *segment = &segments[i];

    uint32_t special = segment->flags & 0xF0000000;
    if (special == 0xE0000000)
    {
      printf_notification("Skipping additional signature segment #%d!\n", i);
      continue;
    }
    else if (special == 0xF0000000)
    {
      printf_notification("Skipping watermark segment #%d!\n", i);
      continue;
    }

    sprintf(state->notifystr,
            "RUNNING\nentry=%s\nentry_number=%d/%d\nstage=decrypt_segment\nsegment=%d/%d\n",
            state->entryname,
            state->entryid,
            state->totalentries,
            i + 1,
            header->segment_count);
    status_write(state->notifystr);

    printf_notification("Decrypting segment %d/%d...\n", i + 1, header->segment_count);

    if ((segment->flags & 0x800) != 0)
    {
      int table_index;
      result = find_table_segment(i, segments, header->segment_count, &table_index);
      if (result != 0)
      {
        printf_notification("Failed to find table for segment #%d!\n", i);
        status_error(state, "find_segment_table", i, -1, 0);
        goto end;
      }

      result = decrypt_segment_blocks(state, i, segment,
                                      table_index, &segments[table_index]);
    }
    else
    {
      result = decrypt_segment(state, i, segment);
    }

    if (result != 0)
    {
      goto end;
    }
  }

  result = 0;

end:
  if (header_data != NULL)
  {
    free(header_data);
  }

  return result;
}

int decrypt_pup(decrypt_state *state, const char *OutputPath)
{
  int result = -1;
  int close_result = 0;
  char ok_path[544];

  if (OutputPath != NULL)
  {
    sprintf(state->output_path, OutputPath, state->entryname);
  }
  else
  {
    sprintf(state->output_path, OUTPUTPATH, state->entryname);
  }

  sprintf(ok_path, "%s.ok", state->output_path);
  unlink(ok_path);

  status_entry(state, "RUNNING", "open_output");
  printf_notification("Creating %s...\n", state->output_path);

  state->output_file = open(state->output_path, O_WRONLY | O_CREAT | O_TRUNC, 0777);
  if (state->output_file == -1)
  {
    int errcode = errno;
    printf_notification("Failed to open %s!\n", state->output_path);
    status_error(state, "open_output", -1, -1, errcode);
    goto end;
  }

  const char *name = state->entryname;

  if (strcmp(name, "PS4UPDATE1.PUP") == 0 || strcmp(name, "PS4UPDATE2.PUP") == 0)
  {
    state->pup_type = 1;
  }

  if (strcmp(name, "PS4UPDATE3.PUP") == 0 || strcmp(name, "PS4UPDATE4.PUP") == 0)
  {
    state->pup_type = 0;
  }

  if (state->pup_type < 0)
  {
    printf_notification("Don't know the type for %s!\n", state->output_path);
    status_error(state, "identify_pup_type", -1, -1, 0);
    goto end;
  }

  result = decrypt_pup_data(state);

end:
  if (state->output_file != -1)
  {
    close_result = close(state->output_file);
    state->output_file = -1;

    if (close_result != 0 && result == 0)
    {
      int errcode = errno;
      printf_notification("Failed to close %s cleanly!\n", state->output_path);
      status_error(state, "close_output", -1, -1, errcode);
      result = -1;
    }
  }

  if (result == 0)
  {
    if (status_touch(ok_path) != 0)
    {
      int errcode = errno;
      printf_notification("Decryption finished but failed to create %s!\n", ok_path);
      status_error(state, "create_ok_marker", -1, -1, errcode);
      result = -1;
    }
    else
    {
      status_entry(state, "RUNNING", "entry_complete");
    }
  }

  return result;
}

int decrypt_pups(const char *InputPath, const char *OutputPath)
{
  int result = -1;
  decrypt_state state = {0};
  state.input_file = -1;
  state.output_file = -1;
  state.device_fd = -1;

  char *strings = (char *)malloc(2048);
  if (strings == NULL)
  {
    status_write("ERROR\nstage=allocate_state_strings\nerror=0\n");
    printf_notification("Failed to allocate state strings!\n");
    goto end;
  }

  state.input_path = strings;
  state.output_path = strings + 512;
  state.entryname = strings + 1024;
  state.notifystr = strings + 1536;

  uint8_t *header_data = NULL;
  size_t blsinitial = 0x400;

  sprintf(state.input_path, "%s", (InputPath != NULL) ? InputPath : INPUTPATH);

  status_write("RUNNING\nstage=open_input\n");
  printf_notification("Opening %s...\n", state.input_path);
  state.input_file = open(state.input_path, O_RDONLY, 0);
  if (state.input_file == -1)
  {
    int errcode = errno;
    sprintf(state.notifystr, "ERROR\nstage=open_input\nerror=%d\n", errcode);
    status_write(state.notifystr);
    printf_notification("Failed to open %s!\n", state.input_path);
    goto end;
  }

  header_data = memalign(0x4000, blsinitial);
  if (header_data == NULL)
  {
    status_write("ERROR\nstage=allocate_bls_header\nerror=0\n");
    printf_notification("Failed to allocate memory for BLS header!\n");
    goto end;
  }

  ssize_t bytesread = readbytes(&state, DIO_RESET, blsinitial,
                                header_data, blsinitial);
  if (bytesread < blsinitial)
  {
    int errcode = errno;
    sprintf(state.notifystr, "ERROR\nstage=read_bls_header\nerror=%d\n", errcode);
    status_write(state.notifystr);
    printf_notification("Failed to read BLS header or BLS header too small!!\n");
    goto end;
  }

  bls_header *header = (bls_header *)header_data;

  if (header->magic != 0x32424C53)
  {
    status_write("ERROR\nstage=validate_bls_magic\nerror=0\n");
    printf_notification("Invalid BLS Header!\n");
    goto end;
  }

  if ((header->file_count < 1) || (header->file_count > 10))
  {
    status_write("ERROR\nstage=validate_entry_count\nerror=0\n");
    printf_notification("Invalid PUP entry count!\n");
    goto end;
  }

  state.totalentries = header->file_count;

  for (uint32_t i = 0; i < header->file_count; i++)
  {
    memcpy(state.entryname, header->entry_list[i].name, sizeof(header->entry_list[i].name));
    state.entryname[sizeof(header->entry_list[i].name)] = '\0';

    state.pup_type = -1;
    state.entryid = i + 1;
    state.input_base_offset = header->entry_list[i].block_offset * 512;
    state.output_file = -1;
    state.output_base_offset = 0;

    status_entry(&state, "RUNNING", "open_encrypt_service");

    state.device_fd = open("/dev/pup_update0", O_RDWR, 0);
    if (state.device_fd < 0)
    {
      int errcode = errno;
      printf_notification("Failed to open /dev/pup_update0!\n");
      status_error(&state, "open_encrypt_service", -1, -1, errcode);
      goto end;
    }

    status_entry(&state, "RUNNING", "verify_bls_header");
    printf_notification("Verifying BLS Header...\n");
    result = encsrv_verify_blsheader(state.device_fd, header_data, blsinitial, 0);

    if (result != 0)
    {
      int errcode = errno;
      printf_notification("Failed while verifying BLS Header! Error: %d (%s)\n",
                          errcode, strerror(errcode));
      status_error(&state, "verify_bls_header", -1, -1, errcode);
      goto end;
    }

    sprintf(state.notifystr,
            "Decrypting \"%s\" (%d/%d)...",
            state.entryname,
            state.entryid,
            state.totalentries);
    printf_notification(state.notifystr);

    result = decrypt_pup(&state, OutputPath);
    if (result != 0)
    {
      goto end;
    }

    close(state.device_fd);
    state.device_fd = -1;
  }

  result = 0;

end:
  if (header_data != NULL)
  {
    free(header_data);
  }

  if (strings != NULL)
  {
    free(strings);
  }

  if (state.input_file != -1)
  {
    close(state.input_file);
    state.input_file = -1;
  }

  if (state.device_fd != -1)
  {
    close(state.device_fd);
    state.device_fd = -1;
  }

  return result;
}
