use zenth_crypto_service::exchange::curve::{PrivateKey as X25519Private, PublicKey as X25519Public};
use zenth_crypto_service::hashing::hash::CryptographicHash;

#[test]
fn ecdh_deterministe_id() {
    let alice_sk_bytes: [u8; 32] = [
        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x10,
        0x21,0x32,0x43,0x54,0x65,0x76,0x87,0x98,0xa9,0xba,0xcb,0xdc,0xed,0xfe,0x0f,0x1e
    ];
    let bob_sk_bytes: [u8; 32] = [
        0xca,0xfe,0xba,0xbe,0xde,0xad,0xbe,0xef,0x00,0x01,0x02,0x03,0x10,0x20,0x30,0x40,
        0x50,0x60,0x70,0x80,0x90,0xa0,0xb0,0xc0,0xd0,0xe0,0xf0,0x0a,0x0b,0x0c,0x0d,0x0e
    ];

    let alice_sk = X25519Private::deserialize(&alice_sk_bytes).expect("alice sk");
    let bob_sk   = X25519Private::deserialize(&bob_sk_bytes).expect("bob sk");
    let alice_pk = alice_sk.public_key().expect("alice pk");
    let bob_pk   = bob_sk.public_key().expect("bob pk");

    let shared_alice = alice_sk.calculate_agreement(&bob_pk).expect("alice dh");
    let shared_bob   = bob_sk.calculate_agreement(&alice_pk).expect("bob dh");
    assert_eq!(shared_alice, shared_bob, "ECDH non symétrique");

    let pk_a = alice_pk.public_key_bytes();
    let pk_b = bob_pk.public_key_bytes();
    let (lo, hi) = if pk_a <= pk_b { (pk_a, pk_b) } else { (pk_b, pk_a) };

    let mut hasher = CryptographicHash::new("SHA-256", 1).expect("sha256");
    hasher.update(&shared_alice);
    hasher.update(lo);            
    hasher.update(hi);            
    let id = hasher.finalize(); 

    let id16 = &id[..16];

    assert!(!id.is_empty());

    println!("Alice pk = {}", hex::encode(alice_pk.public_key_bytes()));
    println!("Bob   pk = {}", hex::encode(bob_pk.public_key_bytes()));
    println!("Shared secret (Alice) = {}", hex::encode(&shared_alice));
    println!("Shared secret (Bob)   = {}", hex::encode(&shared_bob));
    println!("ID 32B = {}", hex::encode(&id));
    println!("ID16  = {}", hex::encode(id16));


}