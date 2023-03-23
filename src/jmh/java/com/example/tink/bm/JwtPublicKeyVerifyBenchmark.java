package com.example.tink.bm;

import static com.google.crypto.tink.KeysetHandle.importKey;

import java.security.GeneralSecurityException;
import java.time.Duration;
import java.time.Instant;

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

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.jwt.JwtPublicKeySign;
import com.google.crypto.tink.jwt.JwtPublicKeyVerify;
import com.google.crypto.tink.jwt.JwtSignatureConfig;
import com.google.crypto.tink.jwt.JwtValidator;
import com.google.crypto.tink.jwt.RawJwt;

@BenchmarkMode(Mode.Throughput)
@Fork(1)
@Threads(8)
@Warmup(iterations = 1)
@Measurement(iterations = 1)
public class JwtPublicKeyVerifyBenchmark {
    @Benchmark
    public void verifyJwt_signedWith1stKey(BmState state, Blackhole bh) throws GeneralSecurityException {
        bh.consume(state.verifier.verifyAndDecode(state.tokens[0], state.validator));
    }

    @Benchmark
    public void verifyJwt_signedWith2ndKey(BmState state, Blackhole bh) throws GeneralSecurityException {
        bh.consume(state.verifier.verifyAndDecode(state.tokens[1], state.validator));
    }

    @Benchmark
    public void verifyJwt_signedWith3rdKey(BmState state, Blackhole bh) throws GeneralSecurityException {
        bh.consume(state.verifier.verifyAndDecode(state.tokens[2], state.validator));
    }

    @Benchmark
    public void verifyJwt_signedWith4thKey(BmState state, Blackhole bh) throws GeneralSecurityException {
        bh.consume(state.verifier.verifyAndDecode(state.tokens[3], state.validator));
    }

    @Benchmark
    public void verifyJwt_signedWith5thKey(BmState state, Blackhole bh) throws GeneralSecurityException {
        bh.consume(state.verifier.verifyAndDecode(state.tokens[4], state.validator));
    }

    @State(Scope.Benchmark)
    public static class BmState {

        public JwtPublicKeyVerify verifier;
        public JwtValidator validator;

        public String[] tokens;

        @Setup
        public void setup() throws GeneralSecurityException {
            JwtSignatureConfig.register();

            final KeysetHandle keyset = newJwtKeysetHaving5Keys();
            verifier = keyset.getPublicKeysetHandle().getPrimitive(JwtPublicKeyVerify.class);
            validator = newValidator();

            System.out.println(keyset.getPublicKeysetHandle().getKeysetInfo());

            tokens = new String[keyset.size()];

            for (int i = 0; i < keyset.size(); i++) {
                final KeysetHandle.Entry entry = keyset.getAt(i);
                final KeysetHandle standaloneKeyset = KeysetHandle
                        .newBuilder()
                        .addEntry(importKey(entry.getKey()).withFixedId(entry.getId()).makePrimary())
                        .build();

                final JwtPublicKeySign signer = standaloneKeyset.getPrimitive(JwtPublicKeySign.class);
                tokens[i] = generateNewJwt(signer);
            }
        }

        @TearDown
        public void teardown() {
            verifier = null;
            validator = null;
            tokens = null;
        }
    }

    static String generateNewJwt(JwtPublicKeySign signer) throws GeneralSecurityException {
        final Instant iat = Instant.now();
        final Instant exp = iat.plusSeconds(3_600 * 10);
        final String iss = "iss";
        final String sub = "sub";

        final RawJwt rawJwt = RawJwt.newBuilder()
                                    .setTypeHeader("JWT")
                                    .setIssuer(iss)
                                    .setIssuedAt(iat)
                                    .setExpiration(exp)
                                    .setSubject(sub)
                                    .build();
        return signer.signAndEncode(rawJwt);
    }

    static JwtValidator newValidator() {
        return JwtValidator.newBuilder()
                           .expectTypeHeader("JWT")
                           .expectIssuedInThePast()
                           .setClockSkew(Duration.ofSeconds(60))
                           .expectIssuer("iss")
                           .build();
    }

    static KeysetHandle newJwtKeysetHaving5Keys() throws GeneralSecurityException {
        final String keyType = "JWT_PS256_3072_F4";

        return KeysetHandle
                .newBuilder()
                .addEntry(KeysetHandle.generateEntryFromParametersName(keyType).withRandomId().makePrimary())
                .addEntry(KeysetHandle.generateEntryFromParametersName(keyType).withRandomId())
                .addEntry(KeysetHandle.generateEntryFromParametersName(keyType).withRandomId())
                .addEntry(KeysetHandle.generateEntryFromParametersName(keyType).withRandomId())
                .addEntry(KeysetHandle.generateEntryFromParametersName(keyType).withRandomId())
                .build();
    }
}
