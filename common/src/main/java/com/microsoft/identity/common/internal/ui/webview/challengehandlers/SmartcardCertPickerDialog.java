package com.microsoft.identity.common.internal.ui.webview.challengehandlers;

import android.app.Activity;
import android.content.Context;
import android.content.DialogInterface;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.RadioButton;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;

import com.microsoft.identity.common.R;

import java.util.List;

//Builds and shows a dialog that allows the user to select a certificate they would like to use to authenticate.
public class SmartcardCertPickerDialog extends SmartcardDialog {

    private List<ClientCertAuthChallengeHandler.YubiKitCertDetails> mCertList;
    private PositiveButtonListener mPositiveButtonListener;
    private NegativeButtonListener mNegativeButtonListener;

    public SmartcardCertPickerDialog(List<ClientCertAuthChallengeHandler.YubiKitCertDetails> certList, Activity activity) {
        super(activity);
        mCertList = certList;
        createDialog();
    }

    protected void createDialog() {
        //Create CertDetailsAdapter
        final CertDetailsAdapter certAdapter = new CertDetailsAdapter(mActivity, mCertList);
        //Must build dialog on UI thread
        mActivity.runOnUiThread(new Runnable() {
            @Override
            public void run() {
                //Start building the dialog.
                AlertDialog.Builder builder = new AlertDialog.Builder(mActivity, R.style.CertAlertDialogTheme)
                        .setTitle(R.string.smartcard_cert_dialog_title)
                        .setSingleChoiceItems(certAdapter, 0, null)
                        //Positive button will pass along the certDetails of the selected row.
                        .setPositiveButton(R.string.smartcard_cert_dialog_positive_button, new DialogInterface.OnClickListener() {
                            @Override
                            public void onClick(final DialogInterface dialog, int which) {
                                //Get the certificate details of the checked row.
                                int checkedPosition = ((AlertDialog) dialog).getListView().getCheckedItemPosition();
                                final ClientCertAuthChallengeHandler.YubiKitCertDetails certDetails = certAdapter.getItem(checkedPosition);
                                if (mPositiveButtonListener != null) {
                                    mPositiveButtonListener.onClick(certDetails);
                                }
                            }
                        })
                        //Negative button should end up cancelling flow.
                        .setNegativeButton(R.string.smartcard_cert_dialog_negative_button, new DialogInterface.OnClickListener() {
                            @Override
                            public void onClick(DialogInterface dialog, int which) {
                                //On request by user, cancel flow.
                                if (mNegativeButtonListener != null) {
                                    mNegativeButtonListener.onClick();
                                }
                            }
                        });
                // Create dialog.
                final AlertDialog alertDialog = builder.create();
                // Set up single checked item logic for cert ListView within dialog.
                final ListView listView = alertDialog.getListView();
                listView.setOnItemClickListener(new AdapterView.OnItemClickListener() {
                    @Override
                    public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                        listView.setItemChecked(position,true);
                        certAdapter.notifyDataSetChanged();
                    }
                });

                //If user touches outside dialog, the default behavior makes the dialog disappear without really doing anything.
                //Adding this line in disables this default behavior so that the user can only exit by hitting the cancel button.
                alertDialog.setCanceledOnTouchOutside(false);
                //Handle back button the same as the negative button.
                alertDialog.setOnCancelListener(new DialogInterface.OnCancelListener() {
                    @Override
                    public void onCancel(DialogInterface dialog) {
                        if (mNegativeButtonListener != null) {
                            mNegativeButtonListener.onClick();
                        }
                    }
                });
                mDialog = alertDialog;
            }
        });
    }

    //Listener interfaces and setters for the dialog buttons.
    public void setPositiveButtonListener(PositiveButtonListener listener) {
        mPositiveButtonListener = listener;
    }

    public void setNegativeButtonListener(NegativeButtonListener listener) {
        mNegativeButtonListener = listener;
    }

    public interface PositiveButtonListener {
        void onClick(ClientCertAuthChallengeHandler.YubiKitCertDetails certDetails);
    }

    public interface NegativeButtonListener {
        void onClick();
    }

    // Adapter for LisView within smartcard certificate picker dialog.
    public static class CertDetailsAdapter extends ArrayAdapter<ClientCertAuthChallengeHandler.YubiKitCertDetails> {

        public CertDetailsAdapter(@NonNull Context context, @NonNull List<ClientCertAuthChallengeHandler.YubiKitCertDetails> certs) {
            super(context, 0, certs);
        }

        @NonNull
        @Override
        public View getView(int position, @Nullable View convertView, @NonNull ViewGroup parent) {
            View item = convertView;
            if (item == null) {
                item = LayoutInflater.from(getContext()).inflate(R.layout.certificate_row_layout, parent, false);
            }
            //Get references to the TextViews within the layout.
            TextView subjectText = item.findViewById(R.id.subjectText);
            TextView issuerText = item.findViewById(R.id.issuerText);
            // Fill in the TextViews with the subject and issuer values.
            ClientCertAuthChallengeHandler.YubiKitCertDetails currentCert = getItem(position);
            subjectText.setText(currentCert.getSubjectText());
            issuerText.setText(currentCert.getIssuerText());
            //Set radio button to be checked/unchecked based on ListView.
            ListView listView = (ListView) parent;
            RadioButton radioButton = item.findViewById(R.id.radioButton);
            radioButton.setChecked(position == listView.getCheckedItemPosition());

            return item;
        }

    }
}
