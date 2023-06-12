package com.example.u6668040.tic_tac_toe;

import android.content.Intent;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;

public class MainMenuActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main_menu);

        final Button btnPlay = findViewById(R.id.btnPlay);
        btnPlay.setClickable(true);
        final Button btnHelp = findViewById(R.id.btnHelp);
        btnHelp.setEnabled(true);
        final Button btnAI = findViewById(R.id.btnAI);
        btnAI.setClickable(true);


        btnPlay.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // ensures that the button can only be pressed once
                btnPlay.setClickable(false);
                btnAI.setClickable(false);
                btnHelp.setClickable(false);
                Intent play = new Intent(getApplicationContext(), GameActivity.class);
                play.putExtra("pvp", true);
                startActivity(play);
                // setContentView(R.layout.activity_game);
            }
        });

        btnAI.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // ensures that the button can only be pressed once
                btnAI.setClickable(false);
                btnPlay.setClickable(false);
                btnHelp.setClickable(false);
                Intent play = new Intent(getApplicationContext(), GameActivity.class);
                play.putExtra("pvp", false);
                startActivity(play);
                // setContentView(R.layout.activity_game);
            }
        });

        btnHelp.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                btnAI.setClickable(false);
                btnPlay.setClickable(false);
                btnHelp.setClickable(false);
                Intent help = new Intent(getApplicationContext(), HelpActivity.class);
                startActivity(help);
            }
        });
    }

    @Override
    protected void onResume(){
        super.onResume();
        Button btnPlay = findViewById(R.id.btnPlay);
        btnPlay.setClickable(true);
        Button btnAI = findViewById(R.id.btnAI);
        btnAI.setClickable(true);
        Button btnHelp = findViewById(R.id.btnHelp);
        btnHelp.setClickable(true);
    }

}
