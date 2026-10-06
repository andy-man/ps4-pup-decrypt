#include <assert.h>

#include "ps4.h"
#include "defines.h"
#include "status.h"

#define KERNEL_CHUNK_SIZE 0x1000
#define KERNEL_CHUNK_NUMBER 0x69B8

int decrypt_pups(const char *InputPath, const char *OutputPath);
uint8_t GetElapsed(uint64_t ResetInterval);

int sock;
time_t prevtime;

uint8_t GetElapsed(uint64_t ResetInterval)
{
  time_t currenttime = time(0);
  uint64_t elapsed = currenttime - prevtime;

  if ((ResetInterval == 0) || (elapsed >= ResetInterval))
  {
    prevtime = currenttime;
    return 1;
  }

  return 0;
}

int _main(struct thread *td)
{
  initKernel();
  initLibc();
  initPthread();
  initNetwork();

#ifdef DEBUG_SOCKET
  struct sockaddr_in server;

  server.sin_len = sizeof(server);
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = DEBUG_ADDR;
  server.sin_port = sceNetHtons(DEBUG_PORT);
  memset(server.sin_zero, 0, sizeof(server.sin_zero));
  sock = sceNetSocket("debug", AF_INET, SOCK_STREAM, 0);
  sceNetConnect(sock, (struct sockaddr *)&server, sizeof(server));

  int flag = 1;
  sceNetSetsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
#endif

  jailbreak();
  initSysUtil();

  GetElapsed(0);

  status_write("RUNNING\nstage=starting\n");
  printf_notification("Running PS4 PUP Decrypter");

  int result = decrypt_pups(INPUTPATH, OUTPUTPATH);

  if (result == 0)
  {
    status_write("DONE\n");
    printf_notification("PS4 PUP Decrypter complete");
  }
  else
  {
    /* decrypt_pups/decrypt_pup_data leave a detailed ERROR status behind. */
    printf_notification("PS4 PUP Decrypter FAILED - check pup_decrypt.status");
  }

  return result;
}
