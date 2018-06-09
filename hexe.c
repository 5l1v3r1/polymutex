/**
  Copyright © 2017 Odzhan. All Rights Reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE. */


#include "hexe.h"

void permute(w128_t *state, int cnt) {
  uint32_t *s=(uint32_t*)&state->w[0];
  int      i;
  
  for (i=0; i<cnt; i++) {
    s[0] += s[1]; 
    s[1]=ROTL32(s[1], 5); 
    s[1] ^= s[0]; 
    s[0]=ROTL32(s[0],16); 
    s[2] += s[3]; 
    s[3]=ROTL32(s[3], 8); 
    s[3] ^= s[2]; 
    s[0] += s[3]; 
    s[3]=ROTL32(s[3],13); 
    s[3] ^= s[0]; 
    s[2] += s[1]; 
    s[1]=ROTL32(s[1], 7); 
    s[1] ^= s[2]; 
    s[2]=ROTL32(s[2],16); 
  }
}
    
uint64_t Hexe(void *in, size_t len, uint64_t nonce)
{
    w128_t s;
    int    idx, i;
    uint8_t *p=(uint8_t*)in;
    w64_t   *seed=(w64_t*)&nonce;
    
    // zero initialize
    memset(s.b, 0, sizeof(s));

    // set 64-bit seed
    s.w[1] = seed->w[0];
    s.w[3] = seed->w[1];
    
    // absorb data
    while (len) {
      idx = MIN(len, HEXE_BLOCK_LEN);
      
      for (i=0; i<idx; i++) {
        s.b[i] ^= p[i];
      }
      
      p += idx;
      len -= idx;
      
      permute(&s, 2);
    }
    // add padding
    s.b[idx] ^= 0x1F;
    s.b[3]   ^= 0x80;
    
    // permute last time
    permute(&s, 4);
    
    // return 64-bit hash
    return s.q[0];
}

#ifdef TEST

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <windows.h>
#include <objbase.h>

#pragma comment(lib, "ole32.lib")

int main(int argc, char *argv[])
{
    w128_t  s, r;
    OLECHAR *guid_str;
    
    if (argc!=2) {
      printf ("usage: hexe_hash <string>\n");
      return 0;
    }
    
    // doesn't matter about source of seed value
    srand(time(0));
    
    // just multiply using golden ratio value
    s.w[0] = rand() * 0x9e3779b9;
    s.w[1] = rand() * 0x9e3779b9;
    
    // derive hash of input string
    s.q[1] = Hexe(argv[1], strlen(argv[1]), s.q[0]);
    
    wprintf(L"Hexe Hash : %016llX%016llX\n", s.q[0], s.q[1]);
    
    // convert to string
    StringFromCLSID((GUID*)&s, &guid_str);
    wprintf(L"GUID      : %s\n", guid_str);
    
    // convert to binary
    CLSIDFromString(guid_str, (GUID*)&r);
    
    wprintf(L"Hexe Hash : %016llX%016llX\n", r.q[0], r.q[1]);
    
    CoTaskMemFree(guid_str);
    return 0;  
}
#endif
