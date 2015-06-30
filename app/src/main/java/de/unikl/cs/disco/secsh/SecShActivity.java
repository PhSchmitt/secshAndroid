package de.unikl.cs.disco.secsh;

import android.os.Bundle;
import android.os.StrictMode;
import android.support.v7.app.ActionBarActivity;
import android.text.TextUtils;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;

import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import de.unikl.cs.disco.engine.SecretShare;
import de.unikl.cs.disco.engine.SecretShare.SplitSecretOutput;
import de.unikl.cs.disco.math.BigIntUtilities;


public class SecShActivity extends ActionBarActivity {


    //constants
    final String hostname = "mptcpsrv1.philippschmitt.de";
    final Integer port = 8080;
    final int numberofsegments = 3;
    final int segmentsneededtorecombine = 2;
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
//                String rawDataString = createRandomString();
                String rawDataString = "123";
                SplitInput splitInput = SplitInput.parse(numberofsegments, segmentsneededtorecombine, rawDataString);
                SplitOutput splitOutput = splitInput.output();
                Log.w("tosend", splitOutput.headerInfo() + splitOutput.allShares());
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
        for (int blubb = 0; blubb < 5; blubb++) {
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
            Log.w("Secret", "" + this.secret);
            ret.splitSecretOutput = secretShare.split(this.secret, this.random);

            return ret;
        }
    }

    public static class SplitOutput {

        private static final String splitChar = "|";

        private final SplitInput splitInput;
        private SplitSecretOutput splitSecretOutput;

        public SplitOutput(SplitInput inSplitInput) {
            splitInput = inSplitInput;
        }

        // ==================================================
        // non public methods
        // ==================================================

        private String headerInfo() {
            final SecretShare.PublicInfo publicInfo = splitSecretOutput.getPublicInfo();

            StringBuilder stringBuilder = new StringBuilder();
            stringBuilder.append(publicInfo.getN());
            stringBuilder.append(splitChar);
            stringBuilder.append(publicInfo.getK());
            stringBuilder.append(splitChar);
            stringBuilder.append(publicInfo.getPrimeModulus());
            stringBuilder.append(splitChar);
            return stringBuilder.toString();
        }

        private String allShares() {
//            StringBuilder stringBuilder = new StringBuilder();

            List<SecretShare.ShareInfo> shares = splitSecretOutput.getShareInfos();
//            Log.w("ShareCnt", "" + shares.size());
//            //TODO this loop is way too slow - how to speed up?
//            //CPU+Memory usage are way too high
//            for (SecretShare.ShareInfo share : shares) {
//                stringBuilder.append(share.getShare());
//                stringBuilder.append(splitChar);
//                Log.w("SB it",stringBuilder.toString());
//
//            }

            List<String> sharesAsString = new ArrayList<>();
            for (SecretShare.ShareInfo share : shares) {
                sharesAsString.add(share.getShare().toString());
            }


            return TextUtils.join(splitChar, sharesAsString) + splitChar;


//            return stringBuilder.toString();

        }
    } // class SplitOutput
}



