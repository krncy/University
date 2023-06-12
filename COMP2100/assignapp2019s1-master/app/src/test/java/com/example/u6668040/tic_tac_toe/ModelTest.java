package com.example.u6668040.tic_tac_toe;

import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;

import Model.Game;

import static org.junit.Assert.*;

/**
 * Tests the implemented Tic-Tac-Toe model
 */
public class ModelTest {
    private Game testGame;

    /**
     * The following three tests are for win conditions
     */

    @Test
    public void testVerticalWin(){
        int[][][] verticalWins = {{{1,1}, {1,2}, {1,3}},
                                    {{2,1}, {2,2}, {2,3}},
                                    {{3,1}, {3,2}, {3,3}}};
        int[][][] dummyMoves = {{{2,1}, {2,2}},
                                {{1,1}, {1,2}},
                                {{1,1}, {1,2}}};

        boolean[] results = new boolean[verticalWins.length];
        boolean[] expected = new boolean[verticalWins.length];
        Arrays.fill(expected, true);

        for (int i=0; i<verticalWins.length; i++){
            testGame = new Game();
            for (int j=0; j<verticalWins[0].length; j++){
                testGame.makeMove(verticalWins[i][j][0], verticalWins[i][j][1]);
                if (j<dummyMoves[0].length){
                    testGame.makeMove(dummyMoves[i][j][0],dummyMoves[i][j][1]);
                }
            }
            results[i] = testGame.hasWinner();
        }

        assertArrayEquals(expected, results);
    }

    @Test
    public void testHorizontalWins(){
        int[][][] horizontalWins = {{{1,1}, {2,1}, {3,1}},
                {{1,2}, {2,2}, {3,2}},
                {{1,3}, {2,3}, {3,3}}};
        int[][][] dummyMoves = {{{2,2}, {2,3}},
                {{1,1}, {3,3}},
                {{1,1}, {2,2}}};

        boolean[] results = new boolean[horizontalWins.length];
        boolean[] expected = new boolean[horizontalWins.length];
        Arrays.fill(expected, true);

        for (int i=0; i<horizontalWins.length; i++){
            testGame = new Game();
            for (int j=0; j<horizontalWins[0].length; j++){
                testGame.makeMove(horizontalWins[i][j][0], horizontalWins[i][j][1]);
                if (j<dummyMoves[0].length){
                    testGame.makeMove(dummyMoves[i][j][0],dummyMoves[i][j][1]);
                }
            }
            testGame.printField();
            results[i] = testGame.hasWinner();
        }

        assertArrayEquals(expected, results);
    }

    @Test
    public void testDiagonalWins(){
        int[][][] diagonalWins = {{{1,1}, {2,2}, {3,3}},
                                  {{1,3}, {2,2}, {3,1}}};
        int[][][] dummyMoves = {{{2,1}, {2,3}},
                {{1,2}, {1,1}}};

        boolean[] results = new boolean[diagonalWins.length];
        boolean[] expected = new boolean[diagonalWins.length];
        Arrays.fill(expected, true);

        for (int i=0; i<diagonalWins.length; i++){
            testGame = new Game();
            for (int j=0; j<diagonalWins[0].length; j++){
                testGame.makeMove(diagonalWins[i][j][0], diagonalWins[i][j][1]);
                if (j<dummyMoves[0].length){
                    testGame.makeMove(dummyMoves[i][j][0],dummyMoves[i][j][1]);
                }
            }
            testGame.printField();
            results[i] = testGame.hasWinner();
        }

        assertArrayEquals(expected, results);
    }


    /**
     * The following test is for some non-win conditions
     */

    @Test
    public void testNotWin(){
        testGame = new Game();
        // blank board has no winner
        assertFalse(testGame.hasWinner());

        int[][][] noWins = {{{1,1},{1,2},{2,2},{2,1},{2,3},{3,1},{3,2},{3,3},{1,3}}};
        boolean[] results = new boolean[noWins.length];
        boolean[] expected = new boolean[noWins.length];
        Arrays.fill(expected, false);

        int i = 0;
        for (int[][] noWinGame : noWins){
            testGame = new Game();
            for (int[] move : noWinGame){
                testGame.makeMove(move[0],move[1]);
            }
            testGame.printField();
            results[i] = testGame.hasWinner();
            i++;
        }

        assertArrayEquals(expected, results);
    }
}
