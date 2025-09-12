use const_str::hex;
use zenth_crypto_service::symetric::serpent_cbc::{
    serpent_256_cbc_encrypt,
    serpent_256_cbc_decrypt,
};


#[test]
fn serpent_cbc_full_cycle() {
    let key = hex!("4e22eb16d964779994222e82192ce9f747da72dc4abe49dfdeeb71d0ffe3796e");
    let iv = hex!("6f8a557ddc0a140c878063a6d5f31d3d");
    let ptext = hex!("30736294a124482a4159");

    // encrypt
    let ctext = serpent_256_cbc_encrypt(&ptext, &key, &iv).expect("valid key/iv");
    assert_eq!(
        hex::encode(ctext.clone()),
        "3235b7889ce4916addb8e4615800a493"
    );

    // decrypt
    let recovered = serpent_256_cbc_decrypt(&ctext, &key, &iv).expect("valid decryption");
    assert_eq!(hex::encode(ptext), hex::encode(&recovered));

    // padding invalid
    assert!(serpent_256_cbc_decrypt(&recovered, &key, &iv).is_err());
    assert!(serpent_256_cbc_decrypt(&ctext, &key, &ctext).is_err());

    // bitflip IV → plaintext déchiffré doit différer de l’original
    let bad_iv = hex!("ef8a557ddc0a140c878063a6d5f31d3d");
    let recovered_bad_iv = serpent_256_cbc_decrypt(&ctext, &key, &bad_iv).expect("valid decryption");

    assert_ne!(&ptext[..], &recovered_bad_iv[..]);

    assert_eq!(
        hex::encode(&recovered_bad_iv),
        "b0736294a124482a4159"
    );




}
