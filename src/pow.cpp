// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>
#include <util/check.h>

#include <algorithm> 
#include <cassert>
#include <cmath>
#include <iostream>
#include <logging.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cctype>

//Fancy popcount implementation
#include <libpopcnt.h>

#ifdef HAVE_GMP
#include <gmpxx.h>
#endif
#ifdef HAVE_CRYPTOPP
#include <cryptopp/sha.h>
#include <cryptopp/blake2.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/scrypt.h>
#include <cryptopp/secblock.h>
#include <cryptopp/sha3.h>
#include <cryptopp/whrlpool.h>
#endif
#include "elliptic/elliptic_curve.h"

uint16_t GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    uint16_t nProofOfWorkLimit = 40;

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then it MUST be a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks
    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

uint16_t CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Compute constants
    const int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    const double nPeriodTimeProportionConsumed = (double)nActualTimespan / (double)params.nPowTargetTimespan;

    //Variable to set difficulty delta
    int32_t nRetarget = 0;

    //Note for mainnet:
    //If it takes more than 1 minute over the target blocktime, reduce difficulty.
    if (nPeriodTimeProportionConsumed >= 1.1f) nRetarget = -1; 
    if (nPeriodTimeProportionConsumed >= 1.2f) nRetarget = -2; 
    if (nPeriodTimeProportionConsumed >= 1.3f) nRetarget = -3; 

    if (nPeriodTimeProportionConsumed <= 0.90f) nRetarget = 1;
    if (nPeriodTimeProportionConsumed <= 0.70f) nRetarget = 2;
    if (nPeriodTimeProportionConsumed <= 0.50f) nRetarget = 3;

    return (uint16_t)pindexLast->nBits + nRetarget;
}


// Check that on difficulty adjustments, the new difficulty does not increase
// or decrease beyond the permitted limits.
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits)
{
    return true;
}

// Bypasses the actual proof of work check during fuzz testing with a simplified validation checking whether
// the most significant bit of the last byte of the hash is set.
bool CheckProofOfWork( const CBlockHeader& block, const Consensus::Params& params) 
{
    //#if (EnableFuzzDeterminism()) return (block.GetHash()[31] & 0x80) == 0;
    return CheckProofOfWorkImpl( block, params);
}

std::optional<arith_uint256> DeriveTarget(unsigned int nBits, const uint256 pow_limit)
{
    return nBits;
}

std::vector<uint8_t> hexStringToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;

    // Ensure even number of digits
    if (hex.size() % 2 != 0) {
        throw std::invalid_argument("Hex string must have an even number of characters");
    }

    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);

        // Validate hex digits
        if (!std::isxdigit(byteString[0]) || !std::isxdigit(byteString[1])) {
            throw std::invalid_argument("Hex string contains non-hex characters");
        }

        uint8_t byte = static_cast<uint8_t>(std::stoul(byteString, nullptr, 16));
        bytes.push_back(byte);
    }

    return bytes;
}

bool CheckProofOfWorkImpl(const CBlockHeader& block, const Consensus::Params& params)
{
    using elliptic::BigInt;
    using elliptic::EllipticCurve;
    using elliptic::Point;

    auto HexToBigInt = [](const std::string& hex) {
        BigInt v{0};
        auto bytes = hexStringToBytes(hex);
        std::reverse(bytes.begin(), bytes.end());
        boost::multiprecision::import_bits(v, bytes.begin(), bytes.end());
        return v;
    };

    //Get gHash(blockheader)
    uint1280 ec_data = gHash(block, params);

    //Extract the EC parameters from the gHash
    BigInt EC_a  = HexToBigInt(ec_data.GetA());
    BigInt EC_b  = HexToBigInt(ec_data.GetB());
    BigInt EC_p  = HexToBigInt(ec_data.GetP());
    BigInt EC_x0 = HexToBigInt(ec_data.GetX());
    BigInt EC_xg = HexToBigInt(ec_data.GetXG());
    BigInt dlog  = HexToBigInt(block.dlog_answer.GetHex());
    BigInt EC_order = HexToBigInt(block.ECorder.GetHex());

    // Get the nBits lower bits from each value.
    // Note that we ensure the bit at position nBits
    // on the prime EC_p is set by setting it. All the other bits are 
    // random and the lo 16-bits are free to change by the miners.
    BigInt mask = BigInt(1) << block.nBits;
    EC_a  %= mask;
    EC_b  %= mask;
    EC_p  = (EC_p + block.pOffset) % mask;
    EC_x0 %= mask;
    EC_xg %= mask;
    EC_p |= (BigInt(1) << (block.nBits - 1));

    //Elliptic Curve is: E: y^2 = x^3 + ax + b mod p
    //    Base point is: P1( EC_x0, y1 ) 
    //  Target point is: p2( EC_xg, y2 )
    //
    //Note: y1,y2 are normalized as follows: y < p - y where $y \in [0,p-1]$.

    // Reject curves whose group order equals the base field size.
    if (EC_order == EC_p) {
        LogPrintf("The Frobenius map degree must be greater than 1.\n");
        return false;
    }

    //The embedding degree is high enough for certain problem transformations
    //to be worthless, i.e. transforming the problem to the prime field case over Z_p^k .
    if (!embedding_safe(EC_order, EC_p)) {
        LogPrintf("PoW error: the embedding degree of the EC must be >= 32. \n");
        return false;
    }

    //Ensure  a and b are not zero.
    if ((EC_a % EC_p) == 0 || (EC_b % EC_p) == 0) {
        LogPrintf("PoW error: Either p | EC_a or p | EC_b.\n");
        return false;
    }
    
    //Ensure p is prime with probability 2^{-64} of not being.
    mpz_class mpz_p(EC_p.convert_to<std::string>());
    if (mpz_probab_prime_p(mpz_p.get_mpz_t(), 32) == 0) {
        LogPrintf("PoW error: p is not prime.\n");
        return false;
    }
    
    //The discriminant should be > 2^40 per the paper on EC PoW blockchain from 2019.
    BigInt D = 16 * (4 * EC_a * EC_a * EC_a + 27 * EC_b * EC_b);
    if (D < (BigInt(1) << 40)) {
        LogPrintf("PoW error: the discriminant must be > 2^40.\n");
        return false;
    }

    //Define EC.
    EllipticCurve curve(EC_a, EC_b, EC_p);

    //Prepare to check if point P1 is on EC.
    BigInt rhs1 = elliptic::mod(EC_x0 * EC_x0 * EC_x0 + EC_a * EC_x0 + EC_b, EC_p);
    BigInt y1 = elliptic::mod_sqrt(rhs1, EC_p);

    //Normalize as stated above: y < p - y.
    if (y1 > EC_p - y1) y1 = EC_p - y1;

    //Ensure x coordinate is in lowes form.
    Point P1(EC_x0%EC_p, y1);

    //Check the point P1 is not the point at infinity.
    if ( P1 == Point::Infinity()) {
        LogPrintf("PoW error: the base point P1 cannot be the point at infinity.\n");
        return false;
    }

    //Check the point P1 is on EC.
    //Check if P1 is on EC. Note that should y2 be a non quadratic residue, this check will fail.
    if (elliptic::mod(y1 * y1 - (EC_x0 * EC_x0 * EC_x0 + EC_a * EC_x0 + EC_b), EC_p) != 0) {
        LogPrintf("PoW error: the base point P1 is not on the EC.\n");
        return false;
    }

    //Prepare to check if point P2 is on EC.
    BigInt rhs2 = elliptic::mod(EC_xg * EC_xg * EC_xg + EC_a * EC_xg + EC_b, EC_p);
    BigInt y2   = elliptic::mod_sqrt(rhs2, EC_p);
    if (y2 > EC_p - y2) y2 = EC_p - y2;
    Point P2(EC_xg%EC_p, y2);
    
    //Check the point P2 is not the point at infinity.
    if ( P2 == Point::Infinity()) {
        LogPrintf("PoW error: the base point P1 cannot be the point at infinity.\n");
        return false;
    }

    //Check if P2 is on EC. Note that should y2 be a non quadratic residue, this check will fail.
    if (elliptic::mod(y2 * y2 - (EC_xg * EC_xg * EC_xg + EC_a * EC_xg + EC_b), EC_p) != 0) {
        LogPrintf("PoW error: target point P2 is not on the EC.\n");
        return false;
    }
   
    ///////////////////////////////////////////////////////////////////////////////////////////
    // We now create a Lemma to avoid using eclib for Elliptic curve arithmetic.
    // I tried using it, but too many segfaults during testing of long chains
    // when calling group_order().
    //
    // I could not find this lemma anywhere, and my profesors experts in EC  
    // have not seen it either. So, here it goes:
    //
    //                           Lemma 1 ( a.k.a Order without Order )
    //
    //  Let p be a prime and E(F_p) an eliptic curve over a prime field, say Zp.
    //
    //  If the following are true,
    //
    //      1. Let q be prime number.
    //      2. q is within the Hasse Bound, so  p + 1 - 2*sqrt(p) < q < p + 1 + 2*sqrt(p).
    //      2. The point $g \in E(F_p)$ has order q.
    //
    //  then #E(F_p) = q. That is, the order of the group of the elliptic curve is q.
    //
    //  Proof:
    //      By Lagrange's Theorem, q | #E(F_p). 
    //      Now we have #E(F_p) = k*q for some integer k another factor of #E(F_p).
    //      By Hasse's bound,   k*q <  p + 1 + 2*sqrt(p).
    //      Note that if k > 1 the bound is broken and we know it holds. Hence, k <=1.
    //      Similarly, p + 1 - 2*sqrt(p) < (k*#E(F_p)) implies k >= 1.
    //      By some sort of group theoretic Squeeze Theorem, we have k = 1, hence #E(F_p) = q. 
    //      
    //     
    //  We now use this fact to avoid using Pari/GP. Math for the win.
    /////////////////////////////////////////////////////////////////////////////////////////////



    // The EC order must be prime with high probability.
    mpz_class mpz_order(EC_order.convert_to<std::string>());
    if (mpz_probab_prime_p(mpz_order.get_mpz_t(), 32) == 0) {
        LogPrintf("PoW error: ECorder is not prime.\n");
        return false;
    }

    // Ensure the order satisfies Hasse's bound.
    BigInt sqrt_p = boost::multiprecision::sqrt(EC_p);
    BigInt upper = BigInt(1) + EC_p + 2 * sqrt_p;
    BigInt lower = BigInt(1) + EC_p - 2 * sqrt_p;
    if (EC_order > upper || EC_order < lower) {
        LogPrintf("PoW error: ECorder fails the Hasse bound for Elliptic Curves.\n");
        return false;
    }

    // Verify that multiplying P1 by the curve order results in the point at
    // infinity.
    Point order_check = curve.multiply(P1, EC_order);
    if (order_check != Point::Infinity()) {
        LogPrintf("PoW error: EC_order*P1 is not the point at infinity.\n");
        return false;
    }
   
    //Point multiply to check dlog solution. 
    Point debug_mul = curve.multiply(P1, dlog);
   
    //Check if dlog = k is a solution to the log problem for P1^k = P2. 
    if (debug_mul == P2) {
        return true;
    }
    LogPrintf("PoW error: dlog*P1 == P2 is false.\n");
    return false;
}

bool embedding_safe(const elliptic::BigInt& n, const elliptic::BigInt& q, uint32_t limit){
    uint32_t degree = 0;
    elliptic::BigInt q_power = q;

    for( ; degree < limit; degree++){
        if ((q_power - 1) % n == 0)
            return false;
        q_power = elliptic::mod(q_power * q, n);
    }

    return true;
}


uint1280 gHash(const CBlockHeader& block, const Consensus::Params& params)
{
    //Get the required data for this block
    uint256 hashPrevBlock = block.hashPrevBlock;
    uint256 hashMerkleRoot = block.hashMerkleRoot;
    uint64_t nNonce = block.nNonce;
    uint32_t nTime = block.nTime;
    uint32_t nVersion = block.nVersion;
    uint16_t nBits = block.nBits;
    
    using namespace CryptoPP;

    //Place data as raw bytes into the password and salt for Scrypt:
    /////////////////////////////////////////////////
    // pass = hashPrevBlock + hashMerkle + nNonce  //
    // salt = version       + nBits      + nTime   //
    /////////////////////////////////////////////////
    byte pass[256 / 8 + 256 / 8 + 64 / 8] = {(byte)0};
    byte salt[32 / 8 + 16 / 8 + 32 / 8] = {(byte)0};

    //SALT: Copy version into the first 4 bytes of the salt.
    memcpy(salt, &nVersion, sizeof(nVersion));

    //SALT: Copy nBits into the next 2 bytes
    int runningLen = sizeof(nVersion);
    memcpy(&salt[runningLen], &nBits, sizeof(nBits));

    //SALT: Copy nTime into the next 4 bytes
    runningLen += sizeof(nBits);
    memcpy(&salt[runningLen], &nTime, sizeof(nTime));

    //PASS: Copy Previous Block Hash into the first 32 bytes
    memcpy(pass, hashPrevBlock.begin(), hashPrevBlock.size());

    //PASS: Copy Merkle Root hash into next 32 bytes
    runningLen = hashPrevBlock.size();
    memcpy(&pass[runningLen], hashMerkleRoot.begin(), hashMerkleRoot.size());

    //PASS: Copy nNonce
    runningLen += hashMerkleRoot.size();
    memcpy(&pass[runningLen], &nNonce, sizeof(nNonce));

    ////////////////////////////////////////////////////////////////////////////////
    //                                Scrypt parameters                           //
    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //  N                  = Iterations count (Affects memory and CPU Usage).     //
    //  r                  = block size ( affects memory and CPU usage).          //
    //  p                  = Parallelism factor. (Number of threads).             //
    //  pass               = Input password.                                      //
    //  salt               = securely-generated random bytes.                     //
    //  derived-key-length = how many bytes to generate as output. Defaults to 32.//
    //                                                                            //
    // For reference, Litecoin has N=1024, r=1, p=1.                              //
    ////////////////////////////////////////////////////////////////////////////////
    Scrypt scrypt;
    word64 N = 1ULL << 9; 
    word64 r = 1ULL << 2;
    word64 p = 1ULL;
    SecByteBlock derived(256);

    //Scrypt Hash to 2048-bits hash.
    scrypt.DeriveKey(derived, derived.size(), pass, sizeof(pass), salt, sizeof(salt), N, r, p); 

    //Consensus parameters
    //By default roundsTotal has always been 1.
    //int roundsTotal = params.hashRounds;
    int roundsTotal = 1;
    
    //Prepare GMP objects
    mpz_t prime_mpz, starting_number_mpz, a_mpz, a_inverse_mpz;
    mpz_init(prime_mpz);
    mpz_init(starting_number_mpz);
    mpz_init(a_mpz);
    mpz_init(a_inverse_mpz);

    for (int round = 0; round < roundsTotal; round++) {
        ///////////////////////////////////////////////////////////////
        //      Memory Expensive Scrypt: 1MB required.              //
        ///////////////////////////////////////////////////////////////
        scrypt.DeriveKey(derived,                     //Final hash
                         derived.size(),              //Final hash number of bytes
                         (const byte*)derived.data(), //Input hash
                         derived.size(),              //Input hash number of bytes
                         salt,                        //Salt
                         sizeof(salt),                //Salt bytes
                         N,                           //Number of rounds
                         r,                           //Sequential Read Sisze
                         p                            //Parallelizable iterations
        );

        ///////////////////////////////////////////////////////////////
        //   Add different types of hashes to the core.              //
        ///////////////////////////////////////////////////////////////
        //Count the bits in previous hash.
        uint64_t pcnt_half1 = popcnt(derived.data(), 128);
        uint64_t pcnt_half2 = popcnt(&derived.data()[128], 128);

        //Hash the first 1024-bits of the 2048-bits hash.
        if (pcnt_half1 % 2 == 0) {
            BLAKE2b bHash;
            bHash.Update((const byte*)derived.data(), 128);
            bHash.Final((byte*)derived.data());
        } else {
            SHA3_512 bHash;
            bHash.Update((const byte*)derived.data(), 128);
            bHash.Final((byte*)derived.data());
        }

        //Hash the second 1024-bits of the 2048-bits hash.
        if (pcnt_half2 % 2 == 0) {
            BLAKE2b bHash;
            bHash.Update((const byte*)(&derived.data()[128]), 128);
            bHash.Final((byte*)(&derived.data()[128]));
        } else {
            SHA3_512 bHash;
            bHash.Update((const byte*)(&derived.data()[128]), 128);
            bHash.Final((byte*)(&derived.data()[128]));
        }

        //////////////////////////////////////////////////////////////
        // Perform expensive math opertions plus simple hashing     //
        //////////////////////////////////////////////////////////////
        //Use the current hash to compute grunt work.
        mpz_import(starting_number_mpz, 32, -1, 8, 0, 0, derived.data()); // -> M = 2048-hash
        mpz_sqrt(starting_number_mpz, starting_number_mpz);               // - \ a = floor( M^(1/2) )
        mpz_set(a_mpz, starting_number_mpz);                              // - /
        mpz_sqrt(starting_number_mpz, starting_number_mpz);               // - \ p = floor( a^(1/2) )
        mpz_nextprime(prime_mpz, starting_number_mpz);                    // - /

        //Compute a^(-1) Mod p
        mpz_invert(a_inverse_mpz, a_mpz, prime_mpz);

        //Xor into current hash digest.
        size_t words = 0;
        uint64_t data[32] = {0};
        uint64_t* hDigest = (uint64_t*)derived.data();
        mpz_export(data, &words, -1, 8, 0, 0, a_inverse_mpz);
        for (int jj = 0; jj < 32; jj++)
            hDigest[jj] ^= data[jj];

        //Check that at most 2048-bits were written
        //Assume 64-bit limbs.
        assert(words <= 32);

        //Compute the population count of a_inverse
        const int32_t irounds = popcnt(data, sizeof(data)) & 0x7f;

        //Branch away
        for (int jj = 0; jj < irounds; jj++) {
            const int32_t br = popcnt(derived.data(), sizeof(derived.data()));

            //Power mod
            mpz_powm_ui(a_inverse_mpz, a_inverse_mpz, irounds, prime_mpz);

            //Get the data out of gmp
            mpz_export(data, &words, -1, 8, 0, 0, a_inverse_mpz);
            assert(words <= 32);

            for (int jj = 0; jj < 32; jj++)
                hDigest[jj] ^= data[jj];

            if (br % 3 == 0) {
                SHA3_512 bHash;
                bHash.Update((const byte*)derived.data(), 128);
                bHash.Final((byte*)derived.data());
            } else if (br % 3 == 2) {
                BLAKE2b sHash;
                sHash.Update((const byte*)(&derived.data()[128]), 128);
                sHash.Final((byte*)(&derived.data()[192]));
            } else {
                Whirlpool wHash;
                wHash.Update((const byte*)(derived.data()), 256);
                wHash.Final((byte*)(&derived.data()[112]));
            }
        }
    }   

    //TODO: Note that we use here a type to that holds 1024-bits instead of the
    //      2048 bits of the hash above. For now this is fine, eventually, we will
    //      need to implement a 2048-bit when the system is factoring 900+ digit numbers.
    //      As this is unlikely to happen any time soon I think we are fine.
    //Copy exactly the number of bytes that contains exactly the low nBits bits.
    uint1280 w;

    //Make sure the values in w are set to 0.
    memset(w.u8_begin_write(), 0, 160);

    //Copy 1280-bits into w
    memcpy(w.u8_begin_write(), derived.begin(), 160 );

    //Clean up GMP types
    mpz_clear(prime_mpz);
    mpz_clear(starting_number_mpz);
    mpz_clear(a_mpz);
    mpz_clear(a_inverse_mpz);

    return w;
}


// Dummy function demonstrating that external libraries can be called from this
// module when enabled at build time.
void DummyPowLibraryUsage()
{
#ifdef HAVE_GMP
    mpz_class a = 1;
    mpz_class b = 2;
    mpz_class c = a + b;
    (void)c;
#endif
#ifdef HAVE_CRYPTOPP
    CryptoPP::SHA256 hash;
    CryptoPP::byte digest[CryptoPP::SHA256::DIGESTSIZE];
    hash.CalculateDigest(digest, nullptr, 0);
    (void)digest;
#endif
}
