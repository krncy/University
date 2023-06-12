package Model;

public enum Type {
    PLAYER1 ("X"),
    PLAYER2 ("O"),
    NONE ("__");

    //the name is for the toString method for printing
    String name;

    public static Type getOtherTurn(Type turn) {
        if (turn == PLAYER1) {
            return PLAYER2;
        } else if (turn == PLAYER2) {
            return PLAYER1;
        } else {
            return NONE;
        }
    }

    Type(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }

    //prints the field nicely
    public static void printField(Type[][] fieldClone) {
        StringBuilder output = new StringBuilder();
        output.append(fieldClone[0][0]);
        output.append("\t");
        output.append(fieldClone[1][0]);
        output.append("\t");
        output.append(fieldClone[2][0]);
        output.append("\n");

        output.append(fieldClone[0][1]);
        output.append("\t");
        output.append(fieldClone[1][1]);
        output.append("\t");
        output.append(fieldClone[2][1]);
        output.append("\n");

        output.append(fieldClone[0][2]);
        output.append("\t");
        output.append(fieldClone[1][2]);
        output.append("\t");
        output.append(fieldClone[2][2]);
        output.append("\n");


        System.out.println(output.toString());
    }
}
