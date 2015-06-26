package de.unikl.cs.disco.softenc;

import android.os.Bundle;
import android.support.v7.app.ActionBarActivity;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;

import java.util.Arrays;

import static de.unikl.cs.disco.softenc.SoftencActivity.Direction.left;
import static de.unikl.cs.disco.softenc.SoftencActivity.Direction.noDirection;
import static de.unikl.cs.disco.softenc.SoftencActivity.Direction.right;
import static de.unikl.cs.disco.softenc.SoftencActivity.Operation.and;
import static de.unikl.cs.disco.softenc.SoftencActivity.Operation.or;


public class SoftencActivity extends ActionBarActivity {

    static {
        System.loadLibrary("softenc");
    }

    //constants
    final String hostname = "mptcpsrv1.philippschmitt.de";
    final Integer port = 8080;
    final char maskToClearDataId = 0x3fff;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_softenc);
        System.loadLibrary("softenc");
        final Button buttonData = (Button) findViewById(R.id.buttonData);

        buttonData.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                String rawDataString = createRandomString();
                DataSet data = new DataSet(rawDataString.length());
                data.fulldecryptedstream = rawDataString.toCharArray();
                encryptStream(data);
                combineData(data);
                sendData(new String(data.aprimes), new String(data.bprimes), new String(data.cprimes), new String(data.dprimes));
                buttonData.setText("Data sent");
            }
        });
    }

    private String createRandomString() {
        StringBuilder sb = new StringBuilder();
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

    private void encryptStream(DataSet data) {
        //TODO: run in parallel if possible
        for (int i = 0; i < data.fulldecryptedstream.length; i++) {
            data.fullencryptedstream[i] = encryptData(data.fulldecryptedstream[i]);
        }
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

    private native int sendUrgent(String jurl, int portno, String jdata, boolean jSetUrgentFlag);

    private char encryptData (char rawChar)
    {
        //rawchar=abcd
        char maska = 0xF000;
        char maskb = 0x0F00;
        char maskc = 0x00F0;
        char maskd = 0x000F;
        char a = maskChar(rawChar,maska,and);
        char b = maskChar(rawChar,maskb,and);
        char c = maskChar(rawChar,maskc,and);
        char d = maskChar(rawChar,maskd,and);
        //move bits that only the last 4 bits are used
        a = shiftBits(a,12,right);
        b = shiftBits(b,8,right);
        c = shiftBits(c,4,right);
        d = shiftBits(d,0,noDirection);

        //XOR-encryption according to Haniotakis, Tragoudas and Kalapodas
        char aprime = (char) (a ^ c);
        char bprime = (char) (b ^ d);
        char cprime = (char) (c ^ b);
        char dprime = (char) (d ^ a ^b);

        //recombine: result = a'b'c'd'
        aprime = shiftBits(aprime,12,left);
        bprime = shiftBits(bprime,8,left);
        cprime = shiftBits(cprime,4,left);
        dprime = shiftBits(dprime,0,noDirection);

        return (char) (aprime | bprime | cprime | dprime);
    }

    /**
     * reads encryptedData, splits it into a'b'c'd' and combines into arrays a' to d'
     */
    private void combineData(DataSet data)
    {
        int j = 0;
        //ensure, that the arrays are empty and of the right size
        Arrays.fill(data.aprimes, (char) 0);
        Arrays.fill(data.bprimes, (char) 0);
        Arrays.fill(data.cprimes, (char) 0);
        Arrays.fill(data.dprimes, (char) 0);

        //TODO: run in parallel if possible
        for (int i = 0; i < data.fullencryptedstream.length; i++) {
            // aprimes=a'1 a'2 a'3 ... => aprimes[0]a'1a'2a'3a'4 => mask
            char maska = 0xF000;
            char maskb = 0x0F00;
            char maskc = 0x00F0;
            char maskd = 0x000F;
            char maskFirst = 0x0FFF;
            char maskSecond = 0xF0FF;
            char maskThird = 0xFF0F;
            char maskFourth = 0xFFF0;
            //TODO: explain what's happening here
            /**
             *
             */
            switch (i%4) {
                case 0:
                    data.aprimes[j] = maskChar(
                            maskChar(data.aprimes[j], maskFirst, and),
                            shiftBits(maskChar(data.fullencryptedstream[i], maska, and), 0, noDirection), or);
                    data.bprimes[j] = maskChar(
                            maskChar(data.bprimes[j], maskFirst, and),
                            shiftBits(maskChar(data.fullencryptedstream[i], maskb, and), 4, left), or);
                    data.cprimes[j] = maskChar(
                            maskChar(data.cprimes[j], maskFirst, and),
                            shiftBits(maskChar(data.fullencryptedstream[i], maskc, and), 8, left), or);
                    data.dprimes[j] = maskChar(
                            maskChar(data.dprimes[j], maskFirst, and),
                            shiftBits(maskChar(data.fullencryptedstream[i], maskd, and), 12, left), or);
                    break;
                case 1:
                    data.aprimes[j] = maskChar(
                            maskChar(data.aprimes[j], maskSecond, and),
                            shiftBits(maskChar(data.fullencryptedstream[i], maska, and), 4, right), or);
                    data.bprimes[j] = maskChar(
                            maskChar(data.bprimes[j], maskSecond, and),
                            shiftBits(maskChar(data.fullencryptedstream[i], maskb, and), 0, noDirection), or);
                    data.cprimes[j] = maskChar(
                            maskChar(data.cprimes[j], maskSecond, and),
                            shiftBits(maskChar(data.fullencryptedstream[i], maskc, and), 4, left), or);
                    data.dprimes[j] = maskChar(
                            maskChar(data.dprimes[j], maskSecond, and),
                            shiftBits(maskChar(data.fullencryptedstream[i], maskd, and), 8, left), or);
                    break;
                case 2:
                    data.aprimes[j] = maskChar(
                            maskChar(data.aprimes[j], maskThird, and),
                            shiftBits(maskChar(data.fullencryptedstream[i], maska, and), 8, right), or);
                    data.bprimes[j] = maskChar(
                            maskChar(data.bprimes[j], maskThird, and),
                            shiftBits(maskChar(data.fullencryptedstream[i], maskb, and), 4, right), or);
                    data.cprimes[j] = maskChar(
                            maskChar(data.cprimes[j], maskThird, and),
                            shiftBits(maskChar(data.fullencryptedstream[i], maskc, and), 0, noDirection), or);
                    data.dprimes[j] = maskChar(
                            maskChar(data.dprimes[j], maskThird, and),
                            shiftBits(maskChar(data.fullencryptedstream[i], maskd, and), 4, left), or);
                    break;
                case 3:
                    data.aprimes[j] = maskChar(
                            maskChar(data.aprimes[j], maskFourth, and),
                            shiftBits(maskChar(data.fullencryptedstream[i], maska, and), 12, right), or);
                    data.bprimes[j] = maskChar(
                            maskChar(data.bprimes[j], maskFourth, and),
                            shiftBits(maskChar(data.fullencryptedstream[i], maskb, and), 8, right), or);
                    data.cprimes[j] = maskChar(
                            maskChar(data.cprimes[j], maskFourth, and),
                            shiftBits(maskChar(data.fullencryptedstream[i], maskc, and), 4, right), or);
                    data.dprimes[j] = maskChar(
                            maskChar(data.dprimes[j], maskFourth, and),
                            shiftBits(maskChar(data.fullencryptedstream[i], maskd, and), 0, noDirection), or);
                    //iterated 4 times => one char filled - get to next one
                    j++;
                    break;
                }

        }

    }

    public char shiftBits(char toShift, int shiftcount, Direction direction)
    {
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

    public char maskChar (char toMask, char mask, Operation operation)
    {
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

    private void sendData(String asend, String bsend, String csend, String dsend)
    {
        /**
         * Bits of dataIdLastStreamIndicatorAndPktCntr:
         * Bit15=most left bit
         * 15,14: dataId: 00=a' 01=b' 10=c' 11=d'
         * 13: must be 1 since leading zeros (especially chars that only contain 0s) get lost in conversion/transmission
         * 12: isLastStream: server listens until packets with bit 12 set for all IDs received
         * 11-0: packet counter for future use
         *
         * Init: Bit 13 set, all others 0
         */
        char dataIdLastStreamIndicatorAndPktCntr = 0x2000;

        try {
                //set isLastStream to 1
                dataIdLastStreamIndicatorAndPktCntr = maskChar(dataIdLastStreamIndicatorAndPktCntr, (char) (0x1000), or);
            sendAprimePkt(asend, dataIdLastStreamIndicatorAndPktCntr);

                // TODO we let the server the time to open a new socket - should be deleted as soon as the Server listens continuously
                Thread.sleep(100);
            sendBprimePkt(bsend, dataIdLastStreamIndicatorAndPktCntr);

                Thread.sleep(100);
            sendCprimePkt(csend, dataIdLastStreamIndicatorAndPktCntr);

                Thread.sleep(100);
            sendDprimePkt(dsend, dataIdLastStreamIndicatorAndPktCntr);
            } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void sendDprimePkt(String dsend, char dataIdLastStreamIndicatorAndPktCntr) {
        //send dprimes
        Log.d("Softenc", "Trying to send dprimes");
        //set dataId to 11 (=d)
        dataIdLastStreamIndicatorAndPktCntr = maskChar(dataIdLastStreamIndicatorAndPktCntr, maskToClearDataId, and);
        char maskDprimeStream = 0xC000;
        dataIdLastStreamIndicatorAndPktCntr = maskChar(dataIdLastStreamIndicatorAndPktCntr, maskDprimeStream, or);
        int errorcode = sendUrgent(hostname, port, dataIdLastStreamIndicatorAndPktCntr + dsend, true);
        if (0 == errorcode) {
            Log.d("Softenc", "dprimes sent successfully");
        } else {
            Log.e("Softenc", "Error in sending dprimes. Error code: " + errorcode);
        }
    }

    private void sendCprimePkt(String csend, char dataIdLastStreamIndicatorAndPktCntr) {
        //send cprimes
        Log.d("Softenc", "Trying to send cprimes");
        //set dataId to 10 (=c)
        dataIdLastStreamIndicatorAndPktCntr = maskChar(dataIdLastStreamIndicatorAndPktCntr, maskToClearDataId, and);
        char maskCprimeStream = 0x8000;
        dataIdLastStreamIndicatorAndPktCntr = maskChar(dataIdLastStreamIndicatorAndPktCntr, maskCprimeStream, or);
        int errorcode = sendUrgent(hostname, port, dataIdLastStreamIndicatorAndPktCntr + csend, false);
        if (0 == errorcode) {
            Log.d("Softenc", "cprimes sent successfully");
        } else {
            Log.e("Softenc", "Error in sending cprimes. Error code: " + errorcode);
        }
    }

    private void sendBprimePkt(String bsend, char dataIdLastStreamIndicatorAndPktCntr) {
        //send bprimes
        Log.d("Softenc", "Trying to send bprimes");
        //set dataId to 01 (=b)
        dataIdLastStreamIndicatorAndPktCntr = maskChar(dataIdLastStreamIndicatorAndPktCntr, maskToClearDataId, and);
        char maskBprimeStream = 0x4000;
        dataIdLastStreamIndicatorAndPktCntr = maskChar(dataIdLastStreamIndicatorAndPktCntr, maskBprimeStream, or);
        int errorcode = sendUrgent(hostname, port, dataIdLastStreamIndicatorAndPktCntr + bsend, false);
        if (0 == errorcode) {
            Log.d("Softenc", "bprimes sent successfully");
        } else {
            Log.e("Softenc", "Error in sending bprimes. Error code: " + errorcode);
        }
    }

    private void sendAprimePkt(String asend, char dataIdLastStreamIndicatorAndPktCntr) {
        //send aprimes
        Log.d("Softenc", "Trying to send aprimes");
        //set dataId to 00 (=a)
        // is same to cleared
        dataIdLastStreamIndicatorAndPktCntr = maskChar(dataIdLastStreamIndicatorAndPktCntr, maskToClearDataId, and);
        int errorcode = sendUrgent(hostname, port, dataIdLastStreamIndicatorAndPktCntr + asend, false);
        if (0 == errorcode) {
            Log.d("Softenc", "aprimes sent successfully");
        } else {
            Log.e("Softenc", "Error in sending aprimes. Error code: " + errorcode);
        }
    }

    public enum Direction
    {
        left,
        right,
        noDirection
    }

    public enum Operation
    {
        and,
        or,
        xor,
        noOperation
    }

    private class DataSet {

        public char[] aprimes;
        public char[] bprimes;
        public char[] cprimes;
        public char[] dprimes;
        public char[] fullencryptedstream;
        public char[] fulldecryptedstream;

        /**
         * @param arraylength = raw data length
         */
        public DataSet(int arraylength) {
            //ensure that we have enough elements if not dividable by 4
            aprimes = new char[(int) Math.ceil(arraylength / 4.0)];
            bprimes = new char[(int) Math.ceil(arraylength / 4.0)];
            cprimes = new char[(int) Math.ceil(arraylength / 4.0)];
            dprimes = new char[(int) Math.ceil(arraylength / 4.0)];
            fullencryptedstream = new char[arraylength];
            fulldecryptedstream = new char[arraylength];
        }

    }

}

