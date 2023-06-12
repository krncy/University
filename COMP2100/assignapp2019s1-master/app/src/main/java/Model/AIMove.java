package Model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class AIMove {
    Node root;

    public AIMove(Type[][] field, Type turn) {
        root = new Node(field, new int[] {}, turn);
    }

    public int[] determineBestMove() {

        if (root.children.size() == 9) {
            return root.children.get((int) Math.random()*8).lastMoveMade;
        }
        if (root.children.size() == 0) {
            //if there are no children then there are no possible moves.
           return null;
        } else {
            int index = 0;
            int highestHeuristic = root.children.get(0).determineHeuristic(root.turn);

            for (int i = 1; i < root.children.size(); i++) {
                int y = root.children.get(i).determineHeuristic(root.turn);

                if (y > highestHeuristic) {
                    index = i;
                    highestHeuristic = y;
                }
            }

            return root.children.get(index).lastMoveMade;
        }
    }

    public class Node {
        Type[][] field;
        int[] lastMoveMade;
        Type turn;
        List<Node> children = new ArrayList<>();

        public Node(Type[][] field, int[] lastMoveMade, Type turn) {
            //create a node and find its children moves
            this.field = field;
            this.lastMoveMade = lastMoveMade;
            this.turn = turn;
            populateChildren();
        }

        public void populateChildren() {

            List<int[]> childrenCoords = findChildren();

            for (int[] i : childrenCoords) {

                //clone the field and "make the move"
                Type[][] fieldClone = new Type[3][3];
                for (int j = 0; j < 3; j++) {
                    for (int k = 0; k < 3; k++) {
                        fieldClone[j][k] = field[j][k];
                    }
                }
                fieldClone[i[0]][i[1]] = turn;

                //create the new node with new field, the last made move, and set it to be the other players turn.
                children.add(new Node(fieldClone, i, Type.getOtherTurn(turn)));
            }

        }

        public int determineHeuristic(Type turn) {
            //if there are no children, then the game is in an end state, and we must assign an arbitrary heuristic to it
            if (children.size() == 0) {
                //if the board is in a winning state assign +1
                if (checkIfWon(turn, field)) {
                    return 1;
                    //if the board is in a losing state assign -1
                } else if (checkIfWon(Type.getOtherTurn(turn), field)) {
                    return -1;
                } else {
                    //if the board is in neither states, it must be a stalemate so assign a 0 to it
                    return 0;
                }
            } else {

                //calculate the fitness of all the children based upon the heuristic and then depending on whos turn it
                //is, return either the min or the max as that nodes heuristic.
                List<Integer> childrenHeuristic = new ArrayList<>();

                for (Node i : children) {
                    childrenHeuristic.add(i.determineHeuristic(turn));
                }

                if (this.turn == turn) {
                    return Collections.max(childrenHeuristic);

                } else {
                    return Collections.min(childrenHeuristic);
                }
            }
        }

        private List<int[]> findChildren() {

            List<int[]> possibleChildren = new ArrayList<>();

            //if the game won, then there cannot be any children, otherwise, consider every spot that a move can be made in.
            if (!(checkIfWon(turn, field) || checkIfWon(Type.getOtherTurn(turn), field))) {
                for (int x = 0; x < 3; x++) {
                    for (int y = 0; y < 3; y++) {
                        if (field[x][y] == Type.NONE) {
                            possibleChildren.add(new int[]{x, y});
                        }
                    }
                }

            }

            return possibleChildren;
        }

    }

    public boolean checkIfWon(Type type, Type[][] field) {
        //possible winning combos
        //first 3 are vertical
        //next 3 are horizontal
        //next 3 are the diagonals
        int[][][] winningCombos = new int[][][]{{{0,0}, {0,1}, {0,2}},
                                                {{1,0}, {1,1}, {1,2}},
                                                {{2,0}, {2,1}, {2,2}},

                                                {{0,0}, {1,0}, {2,0}},
                                                {{0,1}, {1,1}, {2,1}},
                                                {{0,2}, {1,2}, {2,2}},

                                                {{0,0}, {1,1}, {2,2}},
                                                {{0,2}, {1,1}, {2,0}}};

        for (int[][] x : winningCombos) {
            //assume each combo is winning, and check if it isnt by checking if each location has the correct type
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
}