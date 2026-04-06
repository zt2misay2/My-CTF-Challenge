预期利用python `init_by_array` 的长度拓展 128bits的seed传入后会被拆分为4个32bits chunck 

传入 256bits的seed 会被拆为8个32bits chunk

mt是这样构造随机数流的 

```PHP
mt[i] = (mt[i] ^ ((mt[i-1] ^ (mt[i-1] >> 30)) * 1664525U)) 
        + init_key[j] + j;  
j++;
if (j >= key_length) j = 0; 
```

原128bits的周期下 j 的变化是 `0, 1, 2, 3, 0, 1, 2, 3...` 在256bits的周期下 j 的变化是 `0, 1, 2, 3, 4, 5, 6, 7, 0...` 为了保证对齐 可以给128bits按照chunk复制 并且在后面的4个chunk保证取值的 j - 4 也就是

`K'[j] + j == K[j-4] + (j-4)` 这样子就实现了 256bits重放出一样的随机流