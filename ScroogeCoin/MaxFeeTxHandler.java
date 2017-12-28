import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;

public class MaxFeeTxHandler {

    private UTXOPool utxoPool;

    public MaxFeeTxHandler(UTXOPool utxoPool) {
        this.utxoPool = new UTXOPool(utxoPool);
    }

    public boolean isValidTx(Transaction tx) {

        UTXOPool uniqueUtxos = new UTXOPool();

        double previousTxOutSum = 0.0;

        for (int i = 0; i < tx.numInputs(); i++) {

            Transaction.Input in = tx.getInput(i);
            UTXO utxo = new UTXO(in.prevTxHash, in.outputIndex);

            if (!utxoPool.contains(utxo)) // (1)
                return false;

            Transaction.Output output = utxoPool.getTxOutput(utxo);

            if (!Crypto.verifySignature(output.address, tx.getRawDataToSign(i), in.signature)) // (2)
                return false;

            if (uniqueUtxos.contains(utxo)) // (3)
                return false;

            uniqueUtxos.addUTXO(utxo, output);
            previousTxOutSum += output.value;
        }

        double currentTxOutSum = 0;

        for (Transaction.Output out : tx.getOutputs()) {

            if (out.value < 0) // (4)
                return false;

            currentTxOutSum += out.value;
        }

        return previousTxOutSum >= currentTxOutSum; // (5)
    }

    private double calcTxFees(Transaction tx) {

        if (!isValidTx(tx))
            return 0.0;

        double txInSum = 0.0;
        for (Transaction.Input in : tx.getInputs()) {

            UTXO utxo = new UTXO(in.prevTxHash, in.outputIndex);
            if (!utxoPool.contains(utxo))
                continue;

            Transaction.Output txOutput = utxoPool.getTxOutput(utxo);
            txInSum += txOutput.value;
        }

        double txOutSum = 0.0;
        for (Transaction.Output out : tx.getOutputs()) {
            txOutSum += out.value;
        }

        return txInSum - txOutSum;
    }

    /**
     * Sorts transactions by highest fees, uses the highest ones first,
     * invalidating the lower ones in the process
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {

        Set<Transaction> txsSortedByFees = new TreeSet<>((tx1, tx2) -> {
            double tx1Fees = calcTxFees(tx1);
            double tx2Fees = calcTxFees(tx2);
            return Double.valueOf(tx2Fees).compareTo(tx1Fees);
        });

        Collections.addAll(txsSortedByFees, possibleTxs);

        Set<Transaction> validTxs = new HashSet<>();

        for (Transaction tx : txsSortedByFees) {

            if (isValidTx(tx)) {

                validTxs.add(tx);

                for (Transaction.Input in : tx.getInputs()) {
                    UTXO utxo = new UTXO(in.prevTxHash, in.outputIndex);
                    this.utxoPool.removeUTXO(utxo);
                }

                for (int i = 0; i < tx.numOutputs(); i++) {
                    Transaction.Output out = tx.getOutput(i);
                    UTXO utxo = new UTXO(tx.getHash(), i);
                    this.utxoPool.addUTXO(utxo, out);
                }
            }
        }

        Transaction[] validTxArray = new Transaction[validTxs.size()];
        return validTxs.toArray(validTxArray);
    }

}
