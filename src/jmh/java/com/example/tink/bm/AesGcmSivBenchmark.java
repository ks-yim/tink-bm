package com.example.tink.bm;

import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.conscrypt.Conscrypt;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;

@BenchmarkMode(Mode.Throughput)
@Fork(1)
@Threads(8)
@Warmup(iterations = 1)
@Measurement(iterations = 1)
public class AesGcmSivBenchmark {
    @Benchmark
    public void conscrypt_encrypt(ConscryptProviderState state, Blackhole bh) throws GeneralSecurityException {
        bh.consume(state.aesGcmSiv.encrypt(state.originalData, state.aad));
    }

    @Benchmark
    public void conscrypt_decrypt(ConscryptProviderState state, Blackhole bh) throws GeneralSecurityException {
        bh.consume(state.aesGcmSiv.decrypt(state.encryptedData, state.aad));
    }

    @Benchmark
    public void bc_encrypt(BouncyCastleProviderState state, Blackhole bh) throws GeneralSecurityException {
        bh.consume(state.aesGcmSiv.encrypt(state.originalData, state.aad));
    }

    @Benchmark
    public void bc_decrypt(BouncyCastleProviderState state, Blackhole bh) throws GeneralSecurityException {
        bh.consume(state.aesGcmSiv.decrypt(state.encryptedData, state.aad));
    }


    @State(Scope.Benchmark)
    public static class ConscryptProviderState {

        public byte[] originalData = new byte[4096];
        public byte[] aad = new byte[128];
        public byte[] encryptedData;
        public Aead aesGcmSiv;

        private final Provider provider = Conscrypt.newProvider();

        @Setup
        public void setup() throws GeneralSecurityException {
            Security.addProvider(provider);
            AeadConfig.register();

            aesGcmSiv = newAead("AES256_GCM_SIV");

            final SecureRandom random = new SecureRandom();
            random.nextLong();

            random.nextBytes(originalData);
            random.nextBytes(aad);

            encryptedData = aesGcmSiv.encrypt(originalData, aad);
        }

        @TearDown
        public void teardown() {
            Security.removeProvider(provider.getName());
        }
    }

    @State(Scope.Benchmark)
    public static class BouncyCastleProviderState {

        public byte[] originalData = new byte[4096];
        public byte[] aad = new byte[128];
        public byte[] encryptedData;
        public Aead aesGcmSiv;

        @Setup
        public void setup() throws GeneralSecurityException {
            Security.addProvider(new BouncyCastleProvider());
            AeadConfig.register();

            aesGcmSiv = newAead("AES256_GCM_SIV");

            final SecureRandom random = new SecureRandom();
            random.nextLong();

            random.nextBytes(originalData);
            random.nextBytes(aad);

            encryptedData = aesGcmSiv.encrypt(originalData, aad);
        }

        @TearDown
        public void teardown() {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        }
    }

    static Aead newAead(String alg) throws GeneralSecurityException {
        return KeysetHandle.generateNew(KeyTemplates.get(alg)).getPrimitive(Aead.class);
    }
}
