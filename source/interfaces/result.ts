// object returned by the query method of the MySQL class insert or update methods. The object contains the following properties:
export default interface IMySQLResult {
    fieldCount: number;
    affectedRows: number;
    insertId: number;
    serverStatus: number;
    warningCount: number;
    message: string;
    protocol41: boolean;
    changedRows: number;
}
