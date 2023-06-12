package Model;

public class Game {
    //gameBoard indexed x,y || col-1, row-1
    GameBoard gameBoard;
    Type turn;
    boolean gameOver;
    int numberOfMoves;

    public Game() { startNewGame(); }

    public void startNewGame() {
        gameBoard = new GameBoard();
        turn = pickRandomPlayer();
        gameOver = false;
        numberOfMoves = 0;
    }

    public boolean makeMove(int col, int row) {
        //do not allow moves to be made if the game is over
        if (!gameOver) {
            //check a valid col/row was passed into the function
            if (!(row < 1 || row > 3 || col < 1 || col > 3)) {
                //attempted to make the move
                if (gameBoard.changeValue(col - 1, row - 1, turn)) {
                    numberOfMoves++;
                    endTurn();
                    return true;
                }
            }
        }
        return false;
    }

    private void endTurn() {
        if (gameBoard.checkIfWon(turn)) {
            gameOver = true;
        } else if (numberOfMoves == 9) {
            gameOver = true;
        } else {
            changeTurn();
        }
    }

    private void changeTurn() {
       turn = Type.getOtherTurn(turn);
    }

    private Type pickRandomPlayer() {
        int x = (int)(Math.random()*2)+1 ;

        if (x == 1) {
            return Type.PLAYER1;
        }
        if (x == 2) {
            return Type.PLAYER2;
        }
        return Type.NONE;
    }

    public Type[][] getField() {
        return gameBoard.field;
    }

    public void printField() {
        Type.printField(gameBoard.field);
    }

    public boolean isGameOver() {
        return gameOver;
    }

    public Type getTurn() {
        return turn;
    }

    public int[][] findWinningTiles() {
        if (gameBoard.checkIfWon(turn)) {
            return gameBoard.returnWinningLocation(turn);
        }
        return null;
    }

    public boolean hasWinner() {
        return gameBoard.checkIfWon(turn);
    }
}