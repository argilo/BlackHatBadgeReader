package net.argilo.bhbr;

import java.io.UnsupportedEncodingException;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.IntentFilter;
import android.nfc.NdefMessage;
import android.nfc.NfcAdapter;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

public class MainActivity extends Activity {
    private static final String TAG = "BlackHatBadgeReader";
    private NfcAdapter mAdapter;
    private IntentFilter[] mIntentFilters;
    private PendingIntent mPendingIntent;
    private TextView mText;
    
    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        
        mAdapter = NfcAdapter.getDefaultAdapter(this);
        mPendingIntent = PendingIntent.getActivity(
                this, 0, new Intent(this, getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), 0);
        mIntentFilters = new IntentFilter[] {
                new IntentFilter("android.nfc.action.NDEF_DISCOVERED"), 
                new IntentFilter("android.nfc.action.TAG_DISCOVERED")
        };

        mText = (TextView) findViewById(R.id.text);
        if (savedInstanceState != null) {
            String textString = savedInstanceState.getString("TEXT");
            if (textString != null) {
                mText.setText(textString);
            }
        }
    }
    
    @Override
    public void onPause() {
        super.onPause();
        mAdapter.disableForegroundDispatch(this);
    }

    @Override
    public void onResume() {
        super.onResume();
        mAdapter.enableForegroundDispatch(this, mPendingIntent, mIntentFilters, null);
    }
    
    @Override
    protected void onSaveInstanceState(Bundle outState) {
        outState.putString("TEXT", mText.getText().toString());
    }

    public void onNewIntent(Intent intent) {
        byte[] payload = ((NdefMessage)intent.getParcelableArrayExtra("android.nfc.extra.NDEF_MESSAGES")[0]).getRecords()[0].getPayload();
        Log.d(TAG, "Payload hex: " + byteArrayToHexString(payload));
        String plaintext = xteaDecrypt(payload, "F4A9EF2AFC6D");
        Log.d(TAG, "Plaintext: " + plaintext);
        String pieces[] = plaintext.split("\037", -1);
        for (int i = 0; i < pieces.length; i++) {
            Log.d(TAG, "String: " + pieces[i]);
        }
        String decoded = "";
        if (pieces.length >= 29) {
            String piecesOfFirst[] = pieces[0].split("\036", -1);
            if (piecesOfFirst.length >= 2) {
                decoded += "Account ID: " + piecesOfFirst[0] + "\n";
                decoded += "Event ID: " + piecesOfFirst[1] + "\n";
            }
            decoded += "Salutation: " + pieces[1] + "\n";
            decoded += "Firstname: " + pieces[2] + "\n";
            decoded += "Lastname: " + pieces[3] + "\n";
            decoded += "Middlename: " + pieces[4] + "\n";
            decoded += "Suffix: " + pieces[5] + "\n";
            decoded += "Title: " + pieces[6] + "\n";
            decoded += "Company: " + pieces[7] + "\n";
            decoded += "Division: " + pieces[8] + "\n";
            decoded += "Address1: " + pieces[9] + "\n";
            decoded += "Address2: " + pieces[10] + "\n";
            decoded += "Address3: " + pieces[11] + "\n";
            decoded += "City: " + pieces[12] + "\n";
            decoded += "State: " + pieces[13] + "\n";
            decoded += "Zip: " + pieces[14] + "\n";
            decoded += "Country: " + pieces[15] + "\n";
            decoded += "TelCountryCode: " + pieces[16] + "\n";
            decoded += "Phone: " + pieces[17] + "\n";
            decoded += "Mobile: " + pieces[18] + "\n";
            decoded += "Fax: " + pieces[19] + "\n";
            decoded += "Email: " + pieces[20] + "\n";
            decoded += "URL: " + pieces[21] + "\n";
            decoded += "PubCodes: " + pieces[22] + "\n";
            decoded += "PrivCodes: " + pieces[23] + "\n";
            decoded += "Aux1: " + pieces[24] + "\n";
            decoded += "Aux2: " + pieces[25] + "\n";
            decoded += "Aux3: " + pieces[26] + "\n";
            decoded += "Aux4: " + pieces[27] + "\n";
            decoded += "Aux5: " + pieces[28];
        }
        Log.d(TAG, decoded);
        TextView text = (TextView) findViewById(R.id.text);
        text.setText(decoded);
    }
    
    private static String byteArrayToHexString(byte[] input) {
        String hex = "";
        for (int i = 0; i < input.length; i++){
            hex += Integer.toHexString((input[i] >> 4) & 0xf);
            hex += Integer.toHexString(input[i] & 0xf);
        }
        return hex;
    }
    
    private static String xteaDecrypt(byte[] buffer, String keyString) {
        int[] key = formatKey(keyString);
        int[] block = new int[2];
        
        for (int j = 0; j < buffer.length; j += 8) {
            block[0] = 0;
            block[1] = 0;
            for (int k = 0; k < 4; k++) {
                block[0] += (buffer[j + k] & 0xff) << (k * 8);
                block[1] += (buffer[j + k + 4] & 0xff) << (k * 8);
            }
            xteaDecryptBlock(32, block, key);
            for (int k = 0; k < 4; k++) {
                buffer[j + (3 - k)] = (byte) ((block[0] >>> (k * 8)) & 0xff);
                buffer[j + (3 - k) + 4] = (byte) ((block[1] >>> (k * 8)) & 0xff);
            }
        }
        
        String out = "";
        try {
            out = new String(buffer, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            // This should never happen.
            e.printStackTrace();
        }
        while (out.charAt(out.length() - 1) == 0) {
            out = out.substring(0, out.length() - 1);
        }
        return out;
    }
    
    private static int convertStringToInt(String s) {
        int i = 0;
        try {
            byte[] bytes = s.getBytes("ISO8859-1");
            i = (bytes[0] & 0xff);
            i += (bytes[1] & 0xff) << 8;
            i += (bytes[2] & 0xff) << 16;
            i += (bytes[3] & 0xff) << 24;
        } catch (UnsupportedEncodingException e) {
            // This should never happen.
            e.printStackTrace();
        }
        return i;
    }
    
    private static int[] formatKey(String key) {
        int[] keyInt = new int[4];
        if (key.length() > 16) {
            key = key.substring(0, 16);
        }
        while (key.length() < 16) {
            key = key + " ";
        }
        for (int i = 0; i < 4; i++) {
            keyInt[i] = convertStringToInt(key.substring(i*4, i*4 + 4));
        }
        return keyInt;
    }
    
    private static void xteaDecryptBlock(int rounds, int[] v, int[] key) {
        int delta = 0x9e3779b9;
        int sum = delta * rounds;
        for (int i=0; i < rounds; i++) {
            v[1] -= (((v[0] << 4) ^ (v[0] >>> 5)) + v[0]) ^ (sum + key[(sum>>11) & 3]);
            sum -= delta;
            v[0] -= (((v[1] << 4) ^ (v[1] >>> 5)) + v[1]) ^ (sum + key[sum & 3]);
        }
    }
}