package com.example.u6668040.tic_tac_toe;

import android.content.Intent;
import android.content.res.Configuration;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;

import Model.AIMove;
import Model.Game;
import Model.Type;

public class GameActivity extends AppCompatActivity implements View.OnClickListener {

    private Button[][] buttonArray;

    private Game game;
    private boolean pvp;
    private AIMove cpu;
    private boolean cpuFirst;

    @Override
    public void onClick(View v) {
        if (v instanceof Button){
            int id = v.getId();
            playerMove(id);
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_game);

        Intent previous = this.getIntent();
        Bundle extras = previous.getExtras();
        pvp = extras.getBoolean("pvp");


        buttonArray = new Button[][] {{findViewById(R.id.btnGame0),findViewById(R.id.btnGame1),findViewById(R.id.btnGame2)},
                {findViewById(R.id.btnGame3),findViewById(R.id.btnGame4),findViewById(R.id.btnGame5)},
                {findViewById(R.id.btnGame6),findViewById(R.id.btnGame7),findViewById(R.id.btnGame8)}};

        for (Button[] bs : buttonArray) {
            for ( Button b : bs) {
                b.setOnClickListener(this);
            }
        }

        game = new Game();

        int x = (int) (Math.random() * 2);

        cpuFirst = x == 1;

        if (!pvp && cpuFirst) {

            int col = (int) (Math.random()*3);
            int row = (int) (Math.random()*3);

            game.makeMove(col + 1, row + 1);
            // makeMove takes 0 ms
            buttonArray[col][row].setClickable(false);
            // setClickable takes 1 ms
            fillSquares(game.getField());
        }

        // entire if is 5710 ms

    }

    private void playerMove(int id){
        final Button b = findViewById(id);

        String[] s = b.getContentDescription().toString().split(" ");


        if (game.makeMove(Integer.parseInt(s[0]),Integer.parseInt(s[1]))) {
            b.setClickable(false);
            fillSquares(game.getField());
            if (game.isGameOver()) {
                if (game.hasWinner()) {
                    Toast t = Toast.makeText(getApplicationContext(), game.getTurn().toString() + " Wins", Toast.LENGTH_LONG);
                    t.show();
                    showWinningTiles();
                } else {
                    Toast t = Toast.makeText(getApplicationContext(), "It's a TIE!", Toast.LENGTH_LONG);
                    t.show();
                }
                disableButtons();

            } else {
                if (!pvp) {
                    cpu = new AIMove(game.getField(), game.getTurn());
                    int[] bestMove = cpu.determineBestMove();
                    game.makeMove(bestMove[0] + 1, bestMove[1] + 1);
                    buttonArray[bestMove[0]][bestMove[1]].setClickable(false);
                    fillSquares(game.getField());
                    if (game.isGameOver()) {
                        if (game.hasWinner()) {
                            Toast t = Toast.makeText(getApplicationContext(), game.getTurn().toString() + " Wins", Toast.LENGTH_LONG);
                            t.show();
                            showWinningTiles();
                        } else {
                            Toast t = Toast.makeText(getApplicationContext(), "It's a TIE!", Toast.LENGTH_LONG);
                            t.show();
                        }
                        disableButtons();

                    }
                }
            }
        }
    }

    private void disableButtons(){
        findViewById(R.id.btnGame0).setClickable(false);
        findViewById(R.id.btnGame1).setClickable(false);
        findViewById(R.id.btnGame2).setClickable(false);
        findViewById(R.id.btnGame3).setClickable(false);
        findViewById(R.id.btnGame4).setClickable(false);
        findViewById(R.id.btnGame5).setClickable(false);
        findViewById(R.id.btnGame6).setClickable(false);
        findViewById(R.id.btnGame7).setClickable(false);
        findViewById(R.id.btnGame8).setClickable(false);
    }

    private void fillSquares(Type[][] field) {
                for (int i = 0; i < 3; i++) {
            for (int j = 0; j < 3; j++) {
               if (field[i][j] == Type.PLAYER1) {
                   buttonArray[i][j].setText(R.string.playerOne_icon);
               } else if (field[i][j] == Type.PLAYER2) {
                    buttonArray[i][j].setText(R.string.playerTwo_icon);

                }
            }
        }
    }

    private void showWinningTiles() {
        int[][] winningTiles = game.findWinningTiles();
        if (winningTiles != null) {
            for (int[] i : winningTiles) {
                buttonArray[i[0]][i[1]].setBackgroundColor(getResources().getColor(R.color.colorAccent));
            }
        }

    }

    @Override
    public void onConfigurationChanged(Configuration newConfig) {
        super.onConfigurationChanged(newConfig);
    }

}
