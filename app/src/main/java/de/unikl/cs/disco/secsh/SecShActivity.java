package de.unikl.cs.disco.secsh;

import android.os.Bundle;
import android.os.StrictMode;
import android.support.v7.app.ActionBarActivity;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;

import java.io.OutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.List;
import java.util.Random;

import de.unikl.cs.disco.engine.SecretShare;
import de.unikl.cs.disco.engine.SecretShare.ShareInfo;
import de.unikl.cs.disco.engine.SecretShare.SplitSecretOutput;
import de.unikl.cs.disco.math.BigIntUtilities;


public class SecShActivity extends ActionBarActivity {


    //constants
    final String hostname = "mptcpsrv1.philippschmitt.de";
    final Integer port = 8080;
    final String splitIndicator = "|";
    final int numberofsegments = 100;
    final int segmentsneededtorecombine = 95;
    //TODO: Packetsize so festlegen, dass min. 100 packets
    final int packetsize = 1492;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();
        StrictMode.setThreadPolicy(policy);
        setContentView(R.layout.activity_softenc);
        final Button buttonData = (Button) findViewById(R.id.buttonData);

        buttonData.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                String rawDataString = createRandomString();
                SplitInput splitInput = SplitInput.parse(numberofsegments, segmentsneededtorecombine, rawDataString);
                SplitOutput splitOutput = splitInput.output();
                sendData(splitOutput.headerInfo() + splitOutput.allShares());

//                DataSet data = new DataSet(rawDataString.length());
//                data.fulldecryptedstream = rawDataString.toCharArray();
//                encryptStream(data);
//                combineData(data);
//                sendData(new String(data.aprimes), new String(data.bprimes), new String(data.cprimes), new String(data.dprimes));
                buttonData.setText("Data sent");
            }
        });
    }

    private void sendData(String toSend) {
        try {
            Socket socket = new Socket(hostname, port);
            OutputStream ostream = socket.getOutputStream();
            PrintWriter printWriter = new PrintWriter(ostream);
            printWriter.write(toSend);
            printWriter.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String createRandomString() {
        StringBuilder sb = new StringBuilder();
        //TODO ensure, that we have at least 100* packetsize
        for (int blubb = 0; blubb < 10; blubb++) {
            sb.append("Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy ");
            sb.append("eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam ");
            sb.append("voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet ");
            sb.append("clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit ");
            sb.append("amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam ");
            sb.append("nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, ");
            sb.append("sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. ");
            sb.append("Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor ");
            sb.append("sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam ");
            sb.append("1234567890");
        }
        return sb.toString();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_android_ndk1_sample, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }


    public char shiftBits(char toShift, int shiftcount, Direction direction) {
        char tmp = toShift;
        switch (direction) {
            case left:
                tmp <<= shiftcount;
                break;
            case right:
                tmp >>>= shiftcount;
                break;
            case noDirection:
                break;
        }
        return tmp;
    }

    public char maskChar(char toMask, char mask, Operation operation) {
        char tmp = toMask;
        switch (operation) {
            case and:
                tmp &= mask;
                break;
            case or:
                tmp |= mask;
                break;
            case xor:
                tmp ^= mask;
                break;
            case noOperation:
                break;
        }
        return tmp;
    }


    public enum Direction {
        left,
        right,
        noDirection
    }

    public enum Operation {
        and,
        or,
        xor,
        noOperation
    }

    public static class SplitInput {
        // ==================================================
        // instance data
        // ==================================================

        // required arguments:
        private Integer k;
        private Integer n;
        private BigInteger secret;

        // optional:  if null, then do not use modulus
        // default to 384-bit
        // TODO we can't use an appropriate modulus here since it's too expensive on our android device
        private BigInteger modulus = null;

        // optional: the random can be seeded
        private Random random;

        // ==================================================
        // constructors
        // ==================================================
        public static SplitInput parse(Integer totalsegments, Integer segmentsneededtorecombine, String data) {
            SplitInput ret = new SplitInput();

            ret.k = segmentsneededtorecombine;
            ret.n = totalsegments;
            ret.secret = BigIntUtilities.Human.createBigInteger(data);
            ret.random = new SecureRandom();
            // TODO we can't use an appropriate modulus here since it's too expensive on our android device
            ret.modulus = null;
//            ret.modulus = SecretShare.createAppropriateModulusForSecret(ret.secret);
            return ret;
        }

        // ==================================================
        // public methods
        // ==================================================
        public SplitOutput output() {
            SplitOutput ret = new SplitOutput(this);

            SecretShare.PublicInfo publicInfo =
                    new SecretShare.PublicInfo(this.n,
                            this.k,
                            this.modulus, "");

            SecretShare secretShare = new SecretShare(publicInfo);

            ret.splitSecretOutput = secretShare.split(this.secret, this.random);

            return ret;
        }
    }

    public static class SplitOutput {
        private static final String SPACES = "                                              ";

        private static final String splitIndicator = "|";

        private final SplitInput splitInput;
        private SplitSecretOutput splitSecretOutput;

        public SplitOutput(SplitInput inSplitInput) {
            splitInput = inSplitInput;
        }

        // ==================================================
        // non public methods
        // ==================================================

        private static void markedValue(PrintStream out,
                                        String fieldname,
                                        BigInteger n) {
            out.println(fieldname + " = " + n);
        }

        private static void field(PrintStream out,
                                  String label,
                                  String value) {
            if (value != null) {
                String sep;
                String pad;
                if ((label.length() > 0) &&
                        (!label.trim().equals(""))) {
                    pad = label + SplitOutput.SPACES;
                    pad = pad.substring(0, 30);
                    if (value.equals("")) {
                        pad = label;
                        sep = "";
                    } else {
                        sep = ": ";
                    }
                } else {
                    pad = label;
                    sep = "";
                }

                out.println(pad + sep + value);
            }
        }

        private static void printShare(PrintStream out,
                                       ShareInfo share) {
            markedValue(out, "Share (x:" + share.getIndex() + ")", share.getShare());
        }

        private void printSharesOnePerPage(PrintStream out) {
            final List<SecretShare.ShareInfo> shares = splitSecretOutput.getShareInfos();
            boolean first = true;
            for (SecretShare.ShareInfo share : shares) {

                printHeaderInfo(out);

                printShare(out, share);

            }

        }

        private void printHeaderInfo(PrintStream out) {
            final SecretShare.PublicInfo publicInfo = splitSecretOutput.getPublicInfo();

            markedValue(out, "n", BigInteger.valueOf(publicInfo.getN()));
            markedValue(out, "k", BigInteger.valueOf(publicInfo.getK()));
            markedValue(out, "modulus", publicInfo.getPrimeModulus());
        }

        private String headerInfo() {
            final SecretShare.PublicInfo publicInfo = splitSecretOutput.getPublicInfo();

            StringBuilder stringBuilder = new StringBuilder();
            stringBuilder.append(publicInfo.getN());
            stringBuilder.append(splitIndicator);
            stringBuilder.append(publicInfo.getK());
            stringBuilder.append(splitIndicator);
            stringBuilder.append(publicInfo.getPrimeModulus());
            stringBuilder.append(splitIndicator);

            return stringBuilder.toString();
        }

        private void printSharesAllAtOnce(PrintStream out) {
            List<SecretShare.ShareInfo> shares = splitSecretOutput.getShareInfos();
            out.println("");
            for (SecretShare.ShareInfo share : shares) {
                printShare(out, share);
            }
        }

        private String allShares() {
            StringBuilder stringBuilder = new StringBuilder();

            List<SecretShare.ShareInfo> shares = splitSecretOutput.getShareInfos();
            //TODO this loop is way too slow - how to speed up?
            for (SecretShare.ShareInfo share : shares) {
                stringBuilder.append(share.getShare());
                stringBuilder.append(splitIndicator);
            }
            return stringBuilder.toString();

        }
    } // class SplitOutput
}



