package Model;

import java.io.PrintStream;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) {
        Game game = new Game();

        game.printField();
        Scanner scanner = new Scanner(System.in);  // Create a Scanner object

        while (!game.gameOver) {
            System.out.println(game.turn + " To play!");
            int col = scanner.nextInt();
            int row = scanner.nextInt();
            game.makeMove(col,row);
            game.printField();

            AIMove move = new AIMove(game.getField(), game.turn);
            int[] bestMove = move.determineBestMove();
            System.out.println("The AI is playing the move " + (bestMove[0]+1) + " " + (bestMove[1]+1));
            game.makeMove(bestMove[0] + 1, bestMove[1] + 1);
            game.printField();


        }
        System.out.println(game.turn + " Has won the game!");


    }
}
