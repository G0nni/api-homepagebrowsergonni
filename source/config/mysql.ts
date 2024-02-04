import mysql from 'mysql';
import config from './config';

const params = {
    host: config.mysql.host,
    user: config.mysql.user,
    password: config.mysql.password,
    database: config.mysql.database
};

const Connect = async () =>
    new Promise<mysql.Connection>((resolve, reject) => {
        const connection = mysql.createConnection(params);
        connection.connect((err) => {
            if (err) {
                reject(err);
                return;
            }
            resolve(connection);
        });
    });

const Query = <T>(connection: mysql.Connection, query: string, values: any[] = []) =>
    new Promise<mysql.MysqlError | mysql.Query>((resolve, reject) => {
        connection.query(query, values, (error, results) => {
            if (error) {
                reject(error);
                return;
            }

            resolve(results);
        });
    });

export { Connect, Query };
