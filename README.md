# How to run benchmark

```shell
./gradlew --no-daemon clean jmh -Pjmh.includes=^com.example.tink.bm
```

**Note.** Apple Silicon requires a custom build of [`Conscrypt`](https://github.com/google/conscrypt).
