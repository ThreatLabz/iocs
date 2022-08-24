rule BruteRatel_AES
{
    meta:
        org = "Zscaler @Threatlabz"
        author = "Atinderpal Singh (atinderpal[dot]singh[at]zscaler[dot]com, @__atinder__)"
        date = "2022-Aug-23"
        description = "Detect Brute Ratel based on incremetned AES blocks and method to decrement the blocks at runtime"
        reference_hash = "4d09d1412bdb3aaa52786f4276b5265eb3a5e32f"
        
    strings:
        // All AES block incremented by one
        $aes_long_inv = { 53 0a 6b d6 31 37 a6 39 c0 41 a4 9f 82 f4 d8 fc 7d e4 3a 83 9c 30 00 88 35 8f 44 45 c5 df ea cc 55 7c 95 33 a7 c3  }
        $aes_sbox = { 64 7d 78 7c f3 6c 70 c6 31 02 68 2c ff d8 ac 77 cb 83 ca 7e fb 5a 48 f1 ae d5 a3 b0 9d a5 73 c1 b8 fe 94 27 37 40 }
        $aes_round_con = { 8e 02 03 05 09 11 21 41 81 1c 37 6d d9 ac 4e 9b 30 5f bd 64 c7 98 36 6b d5 b4 7e fb f0 c6 92 3a 73 e5 d4 be 62 c3 a0 }
        $aes_mul2 = { 01 03 05 07 09 0b 0d 0f 11 13 15 17 19 1b 1d 1f 21 23 25 27 29 2b 2d 2f 31 33 35 37 39 3b 3d 3f 41 43 45 47 49 4b 4d 4f 51 53 }
        $aes_mul3 = { 01 04 07 06 0d 10 0b 0a 19 1c 1f 1e 15 18 13 12 31 34 37 36 3d 40 3b 3a 29 2c 2f 2e 25 28 23 22 61 64 67 66 6d 70 6b 6a 79 7c }
        $aes_mul9 = { 01 0a 13 1c 25 2e 37 40 49 42 5b 54 6d 66 7f 78 91 9a 83 8c b5 be a7 b0 d9 d2 cb c4 fd f6 ef e8 3c 33 2a 21 20 17 0e 05 74 7b }
        $aes_mul11 = { 01 0c 17 1e 2d 28 3b 32 59 54 4f 46 75 80 63 6a b1 bc a7 ae 9d 98 8b 82 e9 e4 ff f6 c5 d0 d3 da 7c 71 6e 67 58 5d 42 4b 24 }
        $aes_mul13 = { 01 0e 1b 18 35 3a 2f 24 69 66 73 80 5d 52 47 4c d1 de cb c8 e5 ea ff f4 b9 b6 a3 b0 8d 82 97 9c bc b7 a2 ad 90 83 96 99 d4 }
        $aes_mul14 = { 01 0f 1d 13 39 37 25 2b 71 7f 6d 63 49 47 55 5b e1 ef fd f3 d9 d7 c5 cb 91 9f 8d 83 a9 a7 b5 bb dc d6 c8 ca e4 ee 00 f2 ac }
        
        /*
            method responsible for decrementing blocks
            57                                                  push    rdi
            56                                                  push    rsi
            53                                                  push    rbx
            31 C0                                               xor     eax, eax
            48 8D 3D 34 9A 01 00                                lea     rdi, aes_sbox
            48 8D 35 CD 94 01 00                                lea     rsi, aes_mul_2
            48 8D 1D C6 95 01 00                                lea     rbx, aes_mul_3
            4C 8D 1D 1F 99 01 00                                lea     r11, aes_round_con
            4C 8D 15 98 90 01 00                                lea     r10, aes_inv_s
            4C 8D 0D B1 96 01 00                                lea     r9, aes_mul_9
            4C 8D 05 AA 91 01 00                                lea     r8, aes_mul_11
            48 8D 0D A3 92 01 00                                lea     rcx, aes_mul_13
            48 8D 15 9C 93 01 00                                lea     rdx, aes_mul_14
            FE 0C 07                                            dec     byte ptr [rdi+rax]
            FE 0C 06                                            dec     byte ptr [rsi+rax]
            FE 0C 03                                            dec     byte ptr [rbx+rax]
            41 FE 0C 03                                         dec     byte ptr [r11+rax]
            41 FE 0C 02                                         dec     byte ptr [r10+rax]
            41 FE 0C 01                                         dec     byte ptr [r9+rax]
            41 FE 0C 00                                         dec     byte ptr [r8+rax]
            FE 0C 01                                            dec     byte ptr [rcx+rax]
            FE 0C 02                                            dec     byte ptr [rdx+rax]
            48 FF C0                                            inc     rax
            48 3D 00 01 00 00                                   cmp     rax, 100h
            75 D6                                               jnz     short loc_1A9604
            5B                                                  pop     rbx
            5E                                                  pop     rsi
            5F                                                  pop     rdi
            C3                                                  retn
        */
        $decrement_method = { 57 56 53 31 c0 48 8d [5] 48 8d [5] 48 8d [5] 4c 8d [5] 4c 8d [5] 4c 8d [5] 4c 8d [5] 48 8d [5] 48 8d [5] fe 0c 07 fe 0c 06 fe 0c 03 [0-1] fe 0c 03 [0-1] fe 0c 02 [0-1] fe 0c 01 [0-1] fe 0c 00 fe 0c 01 fe 0c 02 48 ff c0 48 3d 00 01 00 00 75 d6 5b 5e 5f c3 }
    condition:
        5 of them and $decrement_method
}
