Welcome!

This is the code for a simple spreadsheeting application.

To open an existing file, enter the command "open <filename>" into the terminal.
If you do not have an existing file you can start from scratch by adding columns and rows.

A file can be saved using the command "save <filename>". This can then be reopened at a later date with the open command.

To add columns, the command "add column <default value>" is used. A name is automatically generated which can be changed with the edit header command. The column will be populated with the default value spesified.

To add rows, the command "add row <default value>" is used. The row will be populated with the default value spesified.

To delete columns, the command "delete column <column number>" is used. This removes the column from the table. Columns are indexed from 0.

To delete rows, the command "delete row <row number>" is used. The row number is referenced from the table with all the values.
	If the row is being tracked, it is also removed from the selection.

To view entries, the command "display all" or "display selection" is used. 
	display all prints the entire content of the spread sheet.
	display selection prints all the values currently being tracked.

To track rows, the commands "track row <row>" or "track rows <starting row> <ending row>" is used.
	The rows refer to the position of the rows in the main spreadsheet.
	This adds the selected rows to the rows which are being tracked which can then be displayed with display selection.
	rows can be untracked with the untrack row/s command.

To untrack rows, the command "untrack row <row>" or "untrack rows <starting row> <ending row>" is used.
	The rows refer to the position of the rows in the tracked rows sub spreadsheet.
	This removes the selected rows from being tracked.

To sort entries, the command "sort all <column number>" or "sort selection <column number>" is used. 
	This sorts the rows based on the values in a column. 
	Either the whole spread sheet or the tracked rows can be sorted by each command respectivley.
	This changes the order the rows are displayed when the display row command is used.

To edit column names, the command "edit header <column> <new name>" is used. Columns are indexed from 0.

To edit cell content, the command "edit <row> <col> <new value>" is used. This updates the row in the order they where added, not on the order that they are currently sorted in.

To find a value the command "find <value>" can be used. This will return all the rows which contain this value