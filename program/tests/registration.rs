use mollusk_svm::Mollusk;
use solana_account::Account;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_system_interface::{instruction::create_account, program::ID as SYSTEM_PROGRAM};
use solana_xmss::SigningKey;
use solana_xmss_example::KEY_ACCOUNT_LEN;

#[test]
fn create_sign_and_verify_leaves() {
    let program = Address::new_from_array([1; 32]);
    let payer = Address::new_from_array([2; 32]);
    let key = Address::new_from_array([3; 32]);
    let elf = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../target/deploy/solana_xmss_example");
    let svm = Mollusk::new(&program, elf.to_str().unwrap());
    let directory = std::env::temp_dir().join(format!("xmss-program-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();

    // Secrets remain in the host key file. Only the public key and signatures go on-chain.
    let mut signer = SigningKey::create(directory.join("tree.key")).unwrap();
    let public_key = signer.verifying_key().to_bytes();
    let first = ([7; 32], signer.sign(&[7; 32]).unwrap());
    let second = ([8; 32], signer.sign(&[8; 32]).unwrap());

    let accounts = vec![
        (payer, Account::new(1_000_000_000, 0, &SYSTEM_PROGRAM)),
        (key, Account::default()),
    ];
    let data = [&[0][..], &public_key[..]].concat();
    let create = Instruction::new_with_bytes(program, &data, vec![AccountMeta::new(key, true)]);
    let instructions = [
        create_account(
            &payer,
            &key,
            svm.sysvars.rent.minimum_balance(KEY_ACCOUNT_LEN),
            KEY_ACCOUNT_LEN as u64,
            &program,
        ),
        create.clone(),
    ];
    let created = svm.process_transaction_instructions(&instructions, &accounts, Some(&payer));
    assert_eq!(created.raw_result, Ok(()));
    let stored = &created
        .resulting_accounts
        .iter()
        .find(|(a, _)| a == &key)
        .unwrap()
        .1;
    assert_eq!(stored.data[0], 1);
    assert_eq!(&stored.data[1..42], &public_key[..]);
    assert_eq!(&stored.data[42..], &[0; 32]);
    eprintln!("create: {} CU", created.compute_units_consumed);
    assert!(
        svm.process_instruction(&create, &created.resulting_accounts)
            .program_result
            .is_err()
    );

    for (owner, len, signer, writable) in [
        (SYSTEM_PROGRAM, KEY_ACCOUNT_LEN, true, true),
        (program, KEY_ACCOUNT_LEN - 1, true, true),
        (program, KEY_ACCOUNT_LEN, false, true),
        (program, KEY_ACCOUNT_LEN, true, false),
    ] {
        let mut bad = create.clone();
        bad.accounts[0].is_signer = signer;
        bad.accounts[0].is_writable = writable;
        let account = Account::new(svm.sysvars.rent.minimum_balance(len), len, &owner);
        assert!(
            svm.process_instruction(&bad, &[(key, account)])
                .program_result
                .is_err()
        );
    }

    // A bitmap allows unused leaves to arrive out of order.
    let mut current = created.resulting_accounts;
    for (digest, signature) in [second, first] {
        let data = [&[1][..], &digest, signature.as_bytes()].concat();
        let verify =
            Instruction::new_with_bytes(program, &data, vec![AccountMeta::new(key, false)]);
        for offset in [1, 33, data.len() - 1] {
            let mut bad = verify.clone();
            bad.data[offset] ^= 1;
            let rejected = svm.process_instruction(&bad, &current);
            assert!(rejected.program_result.is_err());
            assert_eq!(rejected.resulting_accounts, current);
        }
        let mut short = verify.clone();
        short.data.pop();
        let mut trailing = verify.clone();
        trailing.data.push(0);
        let mut readonly = verify.clone();
        readonly.accounts[0].is_writable = false;
        for bad in [short, trailing, readonly] {
            assert!(
                svm.process_instruction(&bad, &current)
                    .program_result
                    .is_err()
            );
        }
        let mut missing = verify.clone();
        missing.accounts.clear();
        assert!(
            svm.process_instruction(&missing, &[])
                .program_result
                .is_err()
        );
        let blank = Account::new(
            svm.sysvars.rent.minimum_balance(KEY_ACCOUNT_LEN),
            KEY_ACCOUNT_LEN,
            &program,
        );
        assert!(
            svm.process_instruction(&verify, &[(key, blank)])
                .program_result
                .is_err()
        );
        // Leaf 256 is outside the tree, so it never indexes the bitmap.
        let mut invalid_leaf = verify.clone();
        invalid_leaf.data[33..37].copy_from_slice(&256u32.to_be_bytes());
        assert!(
            svm.process_instruction(&invalid_leaf, &current)
                .program_result
                .is_err()
        );

        let verified = svm.process_instruction(&verify, &current);
        assert!(
            verified.program_result.is_ok(),
            "{:?}",
            verified.program_result
        );
        assert!(verified.compute_units_consumed < 45_000);
        eprintln!("verify: {} CU", verified.compute_units_consumed);
        // The leaf is used: the same signature is refused.
        let replay = svm.process_instruction(&verify, &verified.resulting_accounts);
        assert!(replay.program_result.is_err());
        assert_eq!(replay.resulting_accounts, verified.resulting_accounts);
        current = verified.resulting_accounts;
    }
    let mut bad = instructions;
    bad[1].data.pop();
    let rejected = svm.process_transaction_instructions(&bad, &accounts, Some(&payer));
    assert!(rejected.raw_result.is_err());
    assert_eq!(rejected.resulting_accounts, accounts);
    std::fs::remove_dir_all(directory).unwrap();
}
