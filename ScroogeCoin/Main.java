/*
 * Main test code for Cousera cryptocurrency assignment1
 * Based on code by Sven Mentl and Pietro Brunetti
 *
 * Copyright:
 * - Sven Mentl
 * - Pietro Brunetti
 * - Bruce Arden
 * - Tero Keski-Valkama
 */

import com.sun.org.apache.xpath.internal.operations.Bool;

import java.math.BigInteger;
import java.security.*;

public class Main {

    public static void main(String[] args) throws NoSuchAlgorithmException, SignatureException {

        /*
         * Generate key pairs, for Scrooge & Alice
         */
        KeyPair pk_scrooge = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        KeyPair pk_alice = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        if (!TestValidTxs(pk_scrooge, pk_alice)) {
            System.out.println("TestValidTxs Failed!");
            System.exit(-1);
        }

        // (1)
        if (!TestInvalidInput(pk_scrooge, pk_alice)) {
            System.out.println("TestInvalidInput Failed!");
            System.exit(-1);
        }

        // (2)
        if (!TestInvalidSignature(pk_scrooge, pk_alice)) {
            System.out.println("TestInvalidSignature Failed!");
            System.exit(-1);
        }

        // (3)
        if (!TestDoubleSpend(pk_scrooge, pk_alice)) {
            System.out.println("TestDoubleSpend Failed!");
            System.exit(-1);
        }

        // (4)
        if (!TestNegativeTxInput(pk_scrooge, pk_alice)) {
            System.out.println("TestNegativeTxInput Failed!");
            System.exit(-1);
        }

        // (5)
        if (!TestOverSpend(pk_scrooge, pk_alice)) {
            System.out.println("TestOverSpend Failed!");
            System.exit(-1);
        }

        // (Extra Credit)
        if (!TestMaxFees(pk_scrooge, pk_alice)) {
            System.out.println("TestMaxFees Failed!");
            System.exit(-1);
        }

        System.out.println("Passed!");
    }

    private static boolean TestValidTxs(KeyPair pk_scrooge, KeyPair pk_alice) throws SignatureException
    {
        /*
         * Set up the root transaction:
         *
         * Generating a root transaction tx out of thin air, so that Scrooge owns a coin of value 10
         * By thin air I mean that this tx will not be validated, I just need it to get
         * a proper Transaction.Output which I then can put in the UTXOPool, which will be passed
         * to the TXHandler
         */
        Tx tx1 = new Tx();
        tx1.addOutput(10.0, pk_scrooge.getPublic());

        // This value has no meaning, but tx.getRawDataToSign(0) will access it in prevTxHash
        byte[] initialHash = BigInteger.valueOf(0).toByteArray();
        tx1.addInput(initialHash, 0);

        tx1.signTx(pk_scrooge.getPrivate(), 0);

        /*
         * Set up the UTXOPool
         * The transaction output of the root transaction is the initial unspent output
         */
        UTXOPool utxoPool = new UTXOPool();
        UTXO utxo = new UTXO(tx1.getHash(), 0);
        utxoPool.addUTXO(utxo, tx1.getOutput(0));

        /*
         * Set up a test Transaction
         */
        Tx tx2 = new Tx();

        // the Transaction.Output of tx at position 0 has a value of 10
        tx2.addInput(tx1.getHash(), 0);

        // I split the coin of value 10 into 3 coins and send all of them for simplicity to
        // the same address (Alice)
        tx2.addOutput(5.0, pk_alice.getPublic());
        tx2.addOutput(3.0, pk_alice.getPublic());
        tx2.addOutput(2.0, pk_alice.getPublic());
        // Note that in the real world fixed-point types would be used for the values, not doubles.
        // Doubles exhibit floating-point rounding errors. This type should be for example BigInteger
        // and denote the smallest coin fractions (Satoshi in Bitcoin).

        // There is only one (at position 0) Transaction.Input in tx2
        // and it contains the coins from Scrooge, therefore I have to sign with the private key from Scrooge
        tx2.signTx(pk_scrooge.getPrivate(), 0);

        /*
         * Start the test
         */
        // Remember that the utxoPool contains a single unspent Transaction.Output which is
        // the coin from Scrooge.
        TxHandler txHandler = new TxHandler(utxoPool);
        boolean tx2IsValid = txHandler.isValidTx(tx2);
        Transaction[] unhandledTxs = new Transaction[]{tx2};
        Transaction[] handledTxs = txHandler.handleTxs(unhandledTxs);

        return tx2IsValid && handledTxs.length == 1;
    }

    private static boolean TestInvalidInput(KeyPair pk_scrooge, KeyPair pk_alice) throws SignatureException
    {
        Tx tx1 = new Tx();
        tx1.addOutput(10.0, pk_scrooge.getPublic());
        byte[] initialHash = BigInteger.valueOf(0).toByteArray();
        tx1.addInput(initialHash, 0);
        tx1.signTx(pk_scrooge.getPrivate(), 0);
        UTXOPool utxoPool = new UTXOPool();
        UTXO utxo = new UTXO(tx1.getHash(), 0);
        utxoPool.addUTXO(utxo, tx1.getOutput(0));

        Tx tx2 = new Tx();
        tx2.addInput(tx1.getHash(), 1);
        tx2.addOutput(5.0, pk_alice.getPublic());
        tx2.addOutput(3.0, pk_alice.getPublic());
        tx2.addOutput(2.0, pk_alice.getPublic());
        tx2.signTx(pk_scrooge.getPrivate(), 0);

        TxHandler txHandler = new TxHandler(utxoPool);
        boolean tx2IsValid = txHandler.isValidTx(tx2);
        Transaction[] unhandledTxs = new Transaction[]{tx2};
        Transaction[] handledTxs = txHandler.handleTxs(unhandledTxs);

        return !tx2IsValid && handledTxs.length == 0;
    }

    private static boolean TestInvalidSignature(KeyPair pk_scrooge, KeyPair pk_alice) throws SignatureException,
            NoSuchAlgorithmException
    {
        Tx tx1 = new Tx();
        tx1.addOutput(10.0, pk_scrooge.getPublic());
        byte[] initialHash = BigInteger.valueOf(0).toByteArray();
        tx1.addInput(initialHash, 0);
        tx1.signTx(pk_scrooge.getPrivate(), 0);
        UTXOPool utxoPool = new UTXOPool();
        UTXO utxo = new UTXO(tx1.getHash(), 0);
        utxoPool.addUTXO(utxo, tx1.getOutput(0));

        Tx tx2 = new Tx();
        tx2.addInput(tx1.getHash(), 0);
        tx2.addOutput(5.0, pk_alice.getPublic());
        tx2.addOutput(3.0, pk_alice.getPublic());
        tx2.addOutput(2.0, pk_alice.getPublic());
        KeyPair pk_eve = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        tx2.signTx(pk_eve.getPrivate(), 0);

        TxHandler txHandler = new TxHandler(utxoPool);
        boolean tx2IsValid = txHandler.isValidTx(tx2);
        Transaction[] unhandledTxs = new Transaction[]{tx2};
        Transaction[] handledTxs = txHandler.handleTxs(unhandledTxs);

        return !tx2IsValid && handledTxs.length == 0;
    }

    private static boolean TestDoubleSpend(KeyPair pk_scrooge, KeyPair pk_alice) throws SignatureException,
            NoSuchAlgorithmException
    {
        Tx tx1 = new Tx();
        tx1.addOutput(10.0, pk_scrooge.getPublic());
        byte[] initialHash = BigInteger.valueOf(0).toByteArray();
        tx1.addInput(initialHash, 0);
        tx1.signTx(pk_scrooge.getPrivate(), 0);
        UTXOPool utxoPool = new UTXOPool();
        UTXO utxo = new UTXO(tx1.getHash(), 0);
        utxoPool.addUTXO(utxo, tx1.getOutput(0));

        Tx tx2 = new Tx();
        tx2.addInput(tx1.getHash(), 0);
        tx2.addOutput(5.0, pk_alice.getPublic());
        tx2.addOutput(3.0, pk_alice.getPublic());
        tx2.addOutput(2.0, pk_alice.getPublic());
        tx2.signTx(pk_scrooge.getPrivate(), 0);

        Tx tx3 = new Tx();
        KeyPair pk_eve = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        tx3.addOutput(10.0, pk_eve.getPublic());
        tx3.addInput(tx1.getHash(), 0);
        tx3.signTx(pk_scrooge.getPrivate(), 0);

        TxHandler txHandler = new TxHandler(utxoPool);
        Transaction[] unhandledTxs = new Transaction[]{tx2, tx3};
        Transaction[] handledTxs = txHandler.handleTxs(unhandledTxs);

        return handledTxs.length == 1;
    }

    private static boolean TestNegativeTxInput(KeyPair pk_scrooge, KeyPair pk_alice) throws SignatureException
    {
        Tx tx1 = new Tx();
        tx1.addOutput(10.0, pk_scrooge.getPublic());
        byte[] initialHash = BigInteger.valueOf(0).toByteArray();
        tx1.addInput(initialHash, 0);
        tx1.signTx(pk_scrooge.getPrivate(), 0);
        UTXOPool utxoPool = new UTXOPool();
        UTXO utxo = new UTXO(tx1.getHash(), 0);
        utxoPool.addUTXO(utxo, tx1.getOutput(0));

        Tx tx2 = new Tx();
        tx2.addInput(tx1.getHash(), 0);
        tx2.addOutput(5.0, pk_alice.getPublic());
        tx2.addOutput(-3.0, pk_alice.getPublic());
        tx2.addOutput(2.0, pk_alice.getPublic());
        tx2.signTx(pk_scrooge.getPrivate(), 0);

        TxHandler txHandler = new TxHandler(utxoPool);
        boolean tx2IsValid = txHandler.isValidTx(tx2);
        Transaction[] unhandledTxs = new Transaction[]{tx2};
        Transaction[] handledTxs = txHandler.handleTxs(unhandledTxs);

        return !tx2IsValid && handledTxs.length == 0;
    }

    private static boolean TestOverSpend(KeyPair pk_scrooge, KeyPair pk_alice) throws SignatureException
    {
        Tx tx1 = new Tx();
        tx1.addOutput(10.0, pk_scrooge.getPublic());
        byte[] initialHash = BigInteger.valueOf(0).toByteArray();
        tx1.addInput(initialHash, 0);
        tx1.signTx(pk_scrooge.getPrivate(), 0);
        UTXOPool utxoPool = new UTXOPool();
        UTXO utxo = new UTXO(tx1.getHash(), 0);
        utxoPool.addUTXO(utxo, tx1.getOutput(0));

        Tx tx2 = new Tx();
        tx2.addInput(tx1.getHash(), 0);
        tx2.addOutput(5.0, pk_alice.getPublic());
        tx2.addOutput(3.0, pk_alice.getPublic());
        tx2.addOutput(2.0, pk_alice.getPublic());
        tx2.addOutput(1.0, pk_alice.getPublic());
        tx2.signTx(pk_scrooge.getPrivate(), 0);

        TxHandler txHandler = new TxHandler(utxoPool);
        boolean tx2IsValid = txHandler.isValidTx(tx2);
        Transaction[] unhandledTxs = new Transaction[]{tx2};
        Transaction[] handledTxs = txHandler.handleTxs(unhandledTxs);

        return !tx2IsValid && handledTxs.length == 0;
    }

    private static boolean TestMaxFees(KeyPair pk_scrooge, KeyPair pk_alice) throws SignatureException
    {
        Tx tx1 = new Tx();
        tx1.addOutput(10.0, pk_scrooge.getPublic());
        byte[] initialHash = BigInteger.valueOf(0).toByteArray();
        tx1.addInput(initialHash, 0);
        tx1.signTx(pk_scrooge.getPrivate(), 0);
        UTXOPool utxoPool = new UTXOPool();
        UTXO utxo = new UTXO(tx1.getHash(), 0);
        utxoPool.addUTXO(utxo, tx1.getOutput(0));

        Tx tx2 = new Tx();
        tx2.addInput(tx1.getHash(), 0);
        tx2.addOutput(10.0, pk_alice.getPublic());
        tx2.signTx(pk_scrooge.getPrivate(), 0);

        Tx tx3 = new Tx();
        tx3.addOutput(9, pk_scrooge.getPublic());
        tx3.addInput(tx1.getHash(), 0);
        tx3.signTx(pk_scrooge.getPrivate(), 0);

        MaxFeeTxHandler txHandler = new MaxFeeTxHandler(utxoPool);

        Transaction[] unhandledTxs = new Transaction[]{tx2, tx3};
        Transaction[] handledTxs = txHandler.handleTxs(unhandledTxs);

        return (handledTxs.length == 1) && (handledTxs[0] == tx3);
    }

    public static class Tx extends Transaction {
        public void signTx(PrivateKey sk, int input) throws SignatureException {
            Signature sig = null;
            try {
                sig = Signature.getInstance("SHA256withRSA");
                sig.initSign(sk);
                sig.update(this.getRawDataToSign(input));
            } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                throw new RuntimeException(e);
            }
            this.addSignature(sig.sign(), input);
            // Note that this method is incorrectly named, and should not in fact override the Java
            // object finalize garbage collection related method.
            this.finalize();
        }
    }
}
