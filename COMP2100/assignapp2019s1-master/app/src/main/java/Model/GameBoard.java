package Model;

public class GameBoard {
    //indexed x,y as in : col-1, row-1
    Type[][] field;

    public GameBoard() {
        field = new Type[][]   {{Type.NONE, Type.NONE, Type.NONE},
                                {Type.NONE, Type.NONE, Type.NONE},
                                {Type.NONE, Type.NONE, Type.NONE}};
    }

    //check if the location is empty, then, if it is change the value and return if it was changed.
    public boolean changeValue(int x, int y, Type type) {
        if (field[x][y] == Type.NONE) {
            field[x][y] = type;
            return true;
        }
        return false;
    }

    public Type getTypeAtLocation(int x, int y) {
        return field[x][y];
    }

    public boolean checkIfWon(Type type) {
        int[][][] winningCombos = new int[][][]{{{0,0}, {0,1}, {0,2}},
                                                {{1,0}, {1,1}, {1,2}},
                                                {{2,0}, {2,1}, {2,2}},

                                                {{0,0}, {1,0}, {2,0}},
                                                {{0,1}, {1,1}, {2,1}},
                                                {{0,2}, {1,2}, {2,2}},

                                                {{0,0}, {1,1}, {2,2}},
                                                {{0,2}, {1,1}, {2,0}}};

        for (int[][] x : winningCombos) {
            boolean won = true;
            for (int[] y : x) {
                won = won && field[y[0]][y[1]] == type;
            }

            if (won) {
                return true;
            }
        }
        return false;
    }

    public int[][] returnWinningLocation(Type type) {
        int[][][] winningCombos = new int[][][]{{{0,0}, {0,1}, {0,2}},
                {{1,0}, {1,1}, {1,2}},
                {{2,0}, {2,1}, {2,2}},

                {{0,0}, {1,0}, {2,0}},
                {{0,1}, {1,1}, {2,1}},
                {{0,2}, {1,2}, {2,2}},

                {{0,0}, {1,1}, {2,2}},
                {{0,2}, {1,1}, {2,0}}};

        for (int[][] x : winningCombos) {
            boolean won = true;
            for (int[] y : x) {
                won = won && field[y[0]][y[1]] == type;
            }

            if (won) {
                return x;
            }
        }
        return null;
    }

}
