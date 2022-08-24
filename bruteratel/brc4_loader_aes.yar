rule BruteRatel_loader_AES{
    meta:
        org = "Zscaler @Threatlabz"
        author = "Atinderpal Singh (atinderpal[dot]singh[at]zscaler[dot]com, @__atinder__)"
        date = "2022-Aug-23"
        description = "Detect Brute Ratel loader based on incremetned AES blocks and method to decrement the blocks at runtime, pushed onto stack"
        reference_hash = "305b7002b65358a447ec6b49c2059271c48b2517"
    strings:
        // All AES block incremented by one
        /*
            48b8 mov     rax, 7de43a839c300088
            50   push    rax
            48b8 mov     rax, c041a49f82f4d8fc
            50   push    rax
        */
        $aes_long_inv_var1 = { 358f4445c5dfeacc 5048b8 7de43a839c300088 5048b8 c041a49f82f4d8fc 5048b8 530a6bd63137a639 }
        $aes_long_inv_var2 = { 8f4445c5dfeacc55 5048b8 e43a839c30008835 5048b8 41a49f82f4d8fc7d 5048b8 0a6bd63137a639c0 }
        $aes_long_inv_var3 = { 4445c5dfeacc557c 5048b8 3a839c300088358f 5048b8 a49f82f4d8fc7de4 5048b8 6bd63137a639c041 }
        $aes_long_inv_var4 = { 45c5dfeacc557c95 5048b8 839c300088358f44 5048b8 9f82f4d8fc7de43a 5048b8 d63137a639c041a4 }
        $aes_long_inv_var5 = { c5dfeacc557c9533 5048b8 9c300088358f4445 5048b8 82f4d8fc7de43a83 5048b8 3137a639c041a49f }
        $aes_long_inv_var6 = { dfeacc557c9533a7 5048b8 300088358f4445c5 5048b8 f4d8fc7de43a839c 5048b8 37a639c041a49f82 }
        $aes_long_inv_var7 = { eacc557c9533a7c3 5048b8 0088358f4445c5df 5048b8 d8fc7de43a839c30 5048b8 a639c041a49f82f4 }
        $aes_long_inv_var8 = { 88358f4445c5dfea 5048b8 fc7de43a839c3000 5048b8 39c041a49f82f4d8 }
        $aes_sbox_var1 = { aed5a3b09da573c1 5048b8 cb83ca7efb5a48f1 5048b8 3102682cffd8ac77 5048b8 647d787cf36c70c6 }
        $aes_sbox_var2 = { d5a3b09da573c1b8 5048b8 83ca7efb5a48f1ae 5048b8 02682cffd8ac77cb 5048b8 7d787cf36c70c631 }
        $aes_sbox_var3 = { a3b09da573c1b8fe 5048b8 ca7efb5a48f1aed5 5048b8 682cffd8ac77cb83 5048b8 787cf36c70c63102 }
        $aes_sbox_var4 = { b09da573c1b8fe94 5048b8 7efb5a48f1aed5a3 5048b8 2cffd8ac77cb83ca 5048b8 7cf36c70c6310268 }
        $aes_sbox_var5 = { 9da573c1b8fe9427 5048b8 fb5a48f1aed5a3b0 5048b8 ffd8ac77cb83ca7e 5048b8 f36c70c63102682c }
        $aes_sbox_var6 = { a573c1b8fe942737 5048b8 5a48f1aed5a3b09d 5048b8 d8ac77cb83ca7efb 5048b8 6c70c63102682cff }
        $aes_sbox_var7 = { 73c1b8fe94273740 5048b8 48f1aed5a3b09da5 5048b8 ac77cb83ca7efb5a 5048b8 70c63102682cffd8 }
        $aes_sbox_var8 = { f1aed5a3b09da573 5048b8 77cb83ca7efb5a48 5048b8 c63102682cffd8ac }
        
        $aes_round_con_var1 = { d5b47efbf0c6923a 5048b8 305fbd64c798366b 5048b8 811c376dd9ac4e9b 5048b8 8e02030509112141 }
        $aes_round_con_var2 = { b47efbf0c6923a73 5048b8 5fbd64c798366bd5 5048b8 1c376dd9ac4e9b30 5048b8 0203050911214181 }
        $aes_round_con_var3 = { 7efbf0c6923a73e5 5048b8 bd64c798366bd5b4 5048b8 376dd9ac4e9b305f 5048b8 030509112141811c }
        $aes_round_con_var4 = { fbf0c6923a73e5d4 5048b8 64c798366bd5b47e 5048b8 6dd9ac4e9b305fbd 5048b8 0509112141811c37 }
        $aes_round_con_var5 = { f0c6923a73e5d4be 5048b8 c798366bd5b47efb 5048b8 d9ac4e9b305fbd64 5048b8 09112141811c376d }
        $aes_round_con_var6 = { c6923a73e5d4be62 5048b8 98366bd5b47efbf0 5048b8 ac4e9b305fbd64c7 5048b8 112141811c376dd9 }
        $aes_round_con_var7 = { 923a73e5d4be62c3 5048b8 366bd5b47efbf0c6 5048b8 4e9b305fbd64c798 5048b8 2141811c376dd9ac }
        $aes_round_con_var8 = { 3a73e5d4be62c3a0 5048b8 6bd5b47efbf0c692 5048b8 9b305fbd64c79836 5048b8 41811c376dd9ac4e }
        
        $aes_mul2_var1 = { 41434547494b4d4f 5048b8 31333537393b3d3f 5048b8 21232527292b2d2f 5048b8 11131517191b1d1f 5048b8 01030507090b0d0f }
        $aes_mul2_var2 = { 434547494b4d4f51 5048b8 333537393b3d3f41 5048b8 232527292b2d2f31 5048b8 131517191b1d1f21 5048b8 030507090b0d0f11 }
        $aes_mul2_var3 = { 4547494b4d4f5153 5048b8 3537393b3d3f4143 5048b8 2527292b2d2f3133 5048b8 1517191b1d1f2123 5048b8 0507090b0d0f1113 }
        $aes_mul2_var4 = { 37393b3d3f414345 5048b8 27292b2d2f313335 5048b8 17191b1d1f212325 5048b8 07090b0d0f111315 }
        $aes_mul2_var5 = { 393b3d3f41434547 5048b8 292b2d2f31333537 5048b8 191b1d1f21232527 5048b8 090b0d0f11131517 }
        $aes_mul2_var6 = { 3b3d3f4143454749 5048b8 2b2d2f3133353739 5048b8 1b1d1f2123252729 5048b8 0b0d0f1113151719 }
        $aes_mul2_var7 = { 3d3f41434547494b 5048b8 2d2f31333537393b 5048b8 1d1f21232527292b 5048b8 0d0f11131517191b }
        $aes_mul2_var8 = { 3f41434547494b4d 5048b8 2f31333537393b3d 5048b8 1f21232527292b2d 5048b8 0f11131517191b1d } 
        $aes_mul3_var1 = { 616467666d706b6a 5048b8 292c2f2e25282322 5048b8 313437363d403b3a 5048b8 191c1f1e15181312 5048b8 010407060d100b0a }
        $aes_mul3_var2 = { 6467666d706b6a79 5048b8 2c2f2e2528232261 5048b8 3437363d403b3a29 5048b8 1c1f1e1518131231 5048b8 0407060d100b0a19 }
        $aes_mul3_var3 = { 67666d706b6a797c 5048b8 2f2e252823226164 5048b8 37363d403b3a292c 5048b8 1f1e151813123134 5048b8 07060d100b0a191c }
        $aes_mul3_var4 = { 2e25282322616467 5048b8 363d403b3a292c2f 5048b8 1e15181312313437 5048b8 060d100b0a191c1f }
        $aes_mul3_var5 = { 2528232261646766 5048b8 3d403b3a292c2f2e 5048b8 1518131231343736 5048b8 0d100b0a191c1f1e }
        $aes_mul3_var6 = { 282322616467666d 5048b8 403b3a292c2f2e25 5048b8 181312313437363d 5048b8 100b0a191c1f1e15 }
        $aes_mul3_var7 = { 2322616467666d70 5048b8 3b3a292c2f2e2528 5048b8 1312313437363d40 5048b8 0b0a191c1f1e1518 }
        $aes_mul3_var8 = { 22616467666d706b 5048b8 3a292c2f2e252823 5048b8 12313437363d403b 5048b8 0a191c1f1e151813 }
        
        $aes_mul9_var1 = { 3c332a2120170e05 5048b8 d9d2cbc4fdf6efe8 5048b8 919a838cb5bea7b0 5048b8 49425b546d667f78 5048b8 010a131c252e3740 }
        $aes_mul9_var2 = { 332a2120170e0574 5048b8 d2cbc4fdf6efe83c 5048b8 9a838cb5bea7b0d9 5048b8 425b546d667f7891 5048b8 0a131c252e374049 }
        $aes_mul9_var3 = { 2a2120170e05747b 5048b8 cbc4fdf6efe83c33 5048b8 838cb5bea7b0d9d2 5048b8 5b546d667f78919a 5048b8 131c252e37404942 }
        $aes_mul9_var4 = { c4fdf6efe83c332a 5048b8 8cb5bea7b0d9d2cb 5048b8 546d667f78919a83 5048b8 1c252e374049425b }
        $aes_mul9_var5 = { fdf6efe83c332a21 5048b8 b5bea7b0d9d2cbc4 5048b8 6d667f78919a838c 5048b8 252e374049425b54 }
        $aes_mul9_var6 = { f6efe83c332a2120 5048b8 bea7b0d9d2cbc4fd 5048b8 667f78919a838cb5 5048b8 2e374049425b546d }
        $aes_mul9_var7 = { efe83c332a212017 5048b8 a7b0d9d2cbc4fdf6 5048b8 7f78919a838cb5be 5048b8 374049425b546d66 }
        $aes_mul9_var8 = { e83c332a2120170e 5048b8 b0d9d2cbc4fdf6ef 5048b8 78919a838cb5bea7 5048b8 4049425b546d667f }
        $aes_mul11_var1 = { 7c716e67585d424b 5048b8 e9e4fff6c5d0d3da 5048b8 b1bca7ae9d988b82 5048b8 59544f467580636a 5048b8 010c171e2d283b32 }
        $aes_mul11_var2 = { 716e67585d424b24 5048b8 e4fff6c5d0d3da7c 5048b8 bca7ae9d988b82e9 5048b8 544f467580636ab1 5048b8 0c171e2d283b3259 }
        $aes_mul11_var3 = { fff6c5d0d3da7c71 5048b8 a7ae9d988b82e9e4 5048b8 4f467580636ab1bc 5048b8 171e2d283b325954 }
        $aes_mul11_var4 = { f6c5d0d3da7c716e 5048b8 ae9d988b82e9e4ff 5048b8 467580636ab1bca7 5048b8 1e2d283b3259544f }
        $aes_mul11_var5 = { c5d0d3da7c716e67 5048b8 9d988b82e9e4fff6 5048b8 7580636ab1bca7ae 5048b8 2d283b3259544f46 }
        $aes_mul11_var6 = { d0d3da7c716e6758 5048b8 988b82e9e4fff6c5 5048b8 80636ab1bca7ae9d 5048b8 283b3259544f4675 }
        $aes_mul11_var7 = { d3da7c716e67585d 5048b8 8b82e9e4fff6c5d0 5048b8 636ab1bca7ae9d98 5048b8 3b3259544f467580 }
        $aes_mul11_var8 = { da7c716e67585d42 5048b8 82e9e4fff6c5d0d3 5048b8 6ab1bca7ae9d988b 5048b8 3259544f46758063 }
        $aes_mul13_var1 = { bcb7a2ad90839699 5048b8 b9b6a3b08d82979c 5048b8 d1decbc8e5eafff4 5048b8 696673805d52474c 5048b8 010e1b18353a2f24 }
        $aes_mul13_var2 = { b7a2ad90839699d4 5048b8 b6a3b08d82979cbc 5048b8 decbc8e5eafff4b9 5048b8 6673805d52474cd1 5048b8 0e1b18353a2f2469 }
        $aes_mul13_var3 = { a3b08d82979cbcb7 5048b8 cbc8e5eafff4b9b6 5048b8 73805d52474cd1de 5048b8 1b18353a2f246966 }
        $aes_mul13_var4 = { b08d82979cbcb7a2 5048b8 c8e5eafff4b9b6a3 5048b8 805d52474cd1decb 5048b8 18353a2f24696673 }
        $aes_mul13_var5 = { 8d82979cbcb7a2ad 5048b8 e5eafff4b9b6a3b0 5048b8 5d52474cd1decbc8 5048b8 353a2f2469667380 }
        $aes_mul13_var6 = { 82979cbcb7a2ad90 5048b8 eafff4b9b6a3b08d 5048b8 52474cd1decbc8e5 5048b8 3a2f24696673805d }
        $aes_mul13_var7 = { 979cbcb7a2ad9083 5048b8 fff4b9b6a3b08d82 5048b8 474cd1decbc8e5ea 5048b8 2f24696673805d52 }
        $aes_mul13_var8 = { 9cbcb7a2ad908396 5048b8 f4b9b6a3b08d8297 5048b8 4cd1decbc8e5eaff 5048b8 24696673805d5247 }
        
        $aes_mul14_var1 = { dcd6c8cae4ee00f2 5048b8 919f8d83a9a7b5bb 5048b8 e1effdf3d9d7c5cb 5048b8 717f6d634947555b 5048b8 010f1d133937252b }
        $aes_mul14_var2 = { d6c8cae4ee00f2ac 5048b8 9f8d83a9a7b5bbdc 5048b8 effdf3d9d7c5cb91 5048b8 7f6d634947555be1 5048b8 0f1d133937252b71 }
        $aes_mul14_var3 = { 8d83a9a7b5bbdcd6 5048b8 fdf3d9d7c5cb919f 5048b8 6d634947555be1ef 5048b8 1d133937252b717f }
        $aes_mul14_var4 = { 83a9a7b5bbdcd6c8 5048b8 f3d9d7c5cb919f8d 5048b8 634947555be1effd 5048b8 133937252b717f6d }
        $aes_mul14_var5 = { a9a7b5bbdcd6c8ca 5048b8 d9d7c5cb919f8d83 5048b8 4947555be1effdf3 5048b8 3937252b717f6d63 }
        $aes_mul14_var6 = { a7b5bbdcd6c8cae4 5048b8 d7c5cb919f8d83a9 5048b8 47555be1effdf3d9 5048b8 37252b717f6d6349 }
        $aes_mul14_var7 = { b5bbdcd6c8cae4ee 5048b8 c5cb919f8d83a9a7 5048b8 555be1effdf3d9d7 5048b8 252b717f6d634947 }
        $aes_mul14_var8 = { bbdcd6c8cae4ee00 5048b8 cb919f8d83a9a7b5 5048b8 5be1effdf3d9d7c5 5048b8 2b717f6d63494755 }
        
        $decrement_method_var1 = { 0001000075d65b5e 5048b8 fe0c0248ffc0483d 5048b8 01??fe0c00fe0c01 5048b8 03??fe0c02??fe0c 5048b8 0c06fe0c03??fe0c 5048b8 ????????fe0c07fe 5048b8 ??????????488d?? 5048b8 8d??????????488d 5048b8 4c8d??????????4c 5048b8 ??4c8d?????????? 5048b8 ????4c8d???????? 5048b8 ??????488d?????? 5048b8 ????????488d???? 5048b8 57565331c0488d?? }
        $decrement_method_var2 = { 01000075d65b5e5f 5048b8 0c0248ffc0483d00 5048b8 ??fe0c00fe0c01fe 5048b8 ??fe0c02??fe0c01 5048b8 06fe0c03??fe0c03 5048b8 ??????fe0c07fe0c 5048b8 ????????488d???? 5048b8 ??????????488d?? 5048b8 8d??????????4c8d 5048b8 4c8d??????????4c 5048b8 ??4c8d?????????? 5048b8 ????488d???????? 5048b8 ??????488d?????? 5048b8 565331c0488d???? }
        $decrement_method_var3 = { 000075d65b5e5fc3 5048b8 0248ffc0483d0001 5048b8 fe0c00fe0c01fe0c 5048b8 fe0c02??fe0c01?? 5048b8 fe0c03??fe0c03?? 5048b8 ????fe0c07fe0c06 5048b8 ??????488d?????? 5048b8 ????????488d???? 5048b8 ??????????4c8d?? 5048b8 8d??????????4c8d 5048b8 4c8d??????????4c 5048b8 ??488d?????????? 5048b8 ????488d???????? 5048b8 5331c0488d?????? }
        $decrement_method_var4 = { 48ffc0483d000100 5048b8 0c00fe0c01fe0c02 5048b8 0c02??fe0c01??fe 5048b8 0c03??fe0c03??fe 5048b8 ??fe0c07fe0c06fe 5048b8 ????488d???????? 5048b8 ??????488d?????? 5048b8 ????????4c8d???? 5048b8 ??????????4c8d?? 5048b8 8d??????????4c8d 5048b8 488d??????????4c 5048b8 ??488d?????????? 5048b8 31c0488d???????? }
        $decrement_method_var5 = { ffc0483d00010000 5048b8 00fe0c01fe0c0248 5048b8 02??fe0c01??fe0c 5048b8 03??fe0c03??fe0c 5048b8 fe0c07fe0c06fe0c 5048b8 ??488d?????????? 5048b8 ????488d???????? 5048b8 ??????4c8d?????? 5048b8 ????????4c8d???? 5048b8 ??????????4c8d?? 5048b8 8d??????????4c8d 5048b8 488d??????????48 5048b8 c0488d?????????? }
        $decrement_method_var6 = { c0483d0001000075 5048b8 fe0c01fe0c0248ff 5048b8 ??fe0c01??fe0c00 5048b8 ??fe0c03??fe0c02 5048b8 0c07fe0c06fe0c03 5048b8 488d??????????fe 5048b8 ??488d?????????? 5048b8 ????4c8d???????? 5048b8 ??????4c8d?????? 5048b8 ????????4c8d???? 5048b8 ??????????4c8d?? 5048b8 8d??????????488d 5048b8 488d??????????48 }
        $decrement_method_var7 = { 483d0001000075d6 5048b8 0c01fe0c0248ffc0 5048b8 fe0c01??fe0c00fe 5048b8 fe0c03??fe0c02?? 5048b8 07fe0c06fe0c03?? 5048b8 8d??????????fe0c 5048b8 488d??????????48 5048b8 ??4c8d?????????? 5048b8 ????4c8d???????? 5048b8 ??????4c8d?????? 5048b8 ????????4c8d???? 5048b8 ??????????488d?? 5048b8 8d??????????488d }
        $decrement_method_var8 = { 3d0001000075d65b 5048b8 01fe0c0248ffc048 5048b8 0c01??fe0c00fe0c 5048b8 0c03??fe0c02??fe 5048b8 fe0c06fe0c03??fe 5048b8 ??????????fe0c07 5048b8 8d??????????488d 5048b8 4c8d??????????48 5048b8 ??4c8d?????????? 5048b8 ????4c8d???????? 5048b8 ??????4c8d?????? 5048b8 ????????488d???? 5048b8 ??????????488d?? }
        
    condition:
        6 of them
}
