import { Request, Response, NextFunction } from 'express';
import logging from '../config/logging';
import { Connect, Query } from '../config/mysql';
import bcrypt from 'bcrypt';
import signJWT from '../functions/signJWT';
import IUser from '../interfaces/user';
import IMySQLResult from '../interfaces/result';
import jwt from 'jsonwebtoken';
import config from '../config/config';

const NAMESPACE = 'users';

const validateToken = (req: Request, res: Response, next: NextFunction) => {
    logging.info(NAMESPACE, 'Token validated, user authorized.');

    return res.status(200).json({
        message: 'Authorized'
    });
};

const whoAmI = (req: Request, res: Response, next: NextFunction) => {
    if (!res.locals.jwt) {
        return res.status(401).json({
            message: 'Unauthorized: No token provided'
        });
    }

    return res.status(200).json({
        user: {
            userId: res.locals.jwt.userId
        }
    });
};
const login = (req: Request, res: Response, next: NextFunction) => {
    let { username, password } = req.body;

    let query = 'SELECT * FROM users WHERE username = ?';
    let values = [username];

    Connect().then((connection) => {
        Query<IUser[]>(connection, query, values)
            .then((users) => {
                if (Array.isArray(users) && users.length !== 1) {
                    return res.status(401).json({
                        message: 'Unauthorized'
                    });
                }

                let user = users as unknown as IUser[];

                bcrypt.compare(password, user[0].password, (error, result) => {
                    if (error) {
                        logging.error(NAMESPACE, error.message, error);

                        return res.status(401).json({
                            message: 'Unauthorized'
                        });
                    } else if (result) {
                        console.log(user[0].id);
                        signJWT(user[0].id, (error, token) => {
                            if (error) {
                                logging.error(NAMESPACE, error.message, error);

                                return res.status(401).json({
                                    message: 'Unauthorized'
                                });
                            } else if (token) {
                                res.cookie('token', token, { httpOnly: true, sameSite: 'strict' });
                                return res.status(200).json({
                                    token,
                                    user: user[0]
                                });
                            }
                        });
                    }
                });
            })
            .catch((error) => {
                logging.error(NAMESPACE, error.message, error);
                return res.status(500).json({
                    message: error.message,
                    error
                });
            })
            .finally(() => {
                connection.end();
            });
    });
};

const createUser = (req: Request, res: Response, next: NextFunction) => {
    logging.info(NAMESPACE, 'Creating user.');

    let { username, email, password, favorites } = req.body;
    let favoritesString = JSON.stringify(favorites);

    // Hash and salt the password
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
            logging.error(NAMESPACE, err.message, err);

            return res.status(500).json({
                message: err.message,
                error: err
            });
        }

        let checkUsernameQuery = 'SELECT * FROM users WHERE username = ?';
        let checkUsernameValues = [username];

        Connect()
            .then((connection) => {
                Query(connection, checkUsernameQuery, checkUsernameValues)
                    .then((results) => {
                        if (Array.isArray(results) && results.length > 0) {
                            return res.status(400).json({
                                message: 'Username already taken'
                            });
                        }

                        let insertUserQuery = 'INSERT INTO users (username, email, password, favorites) VALUES (?, ?, ?, ?)';
                        let insertUserValues = [username, email, hashedPassword, favoritesString];

                        Query<IMySQLResult>(connection, insertUserQuery, insertUserValues)
                            .then((result) => {
                                logging.info(NAMESPACE, 'User created: ', result);
                                return res.status(201).json({
                                    result
                                });
                            })
                            .catch((error) => {
                                logging.error(NAMESPACE, error.message, error);

                                return res.status(500).json({
                                    message: error.message,
                                    error
                                });
                            })
                            .finally(() => {
                                connection.end();
                            });
                    })
                    .catch((error) => {
                        logging.error(NAMESPACE, error.message, error);

                        return res.status(500).json({
                            message: error.message,
                            error
                        });
                    });
            })
            .catch((error) => {
                logging.error(NAMESPACE, error.message, error);

                return res.status(500).json({
                    message: error.message,
                    error
                });
            });
    });
};

// delete all users
const deleteAllUsers = (req: Request, res: Response, next: NextFunction) => {
    logging.info(NAMESPACE, 'Deleting all users.');

    let query = 'DELETE FROM users';

    Connect()
        .then((connection) => {
            Query(connection, query)
                .then((results) => {
                    return res.status(200).json({ results });
                })
                .catch((error) => {
                    logging.error(NAMESPACE, error.message, error);

                    return res.status(500).json({
                        message: error.message,
                        error
                    });
                })
                .finally(() => {
                    connection.end();
                });
        })
        .catch((error) => {
            logging.error(NAMESPACE, error.message, error);

            return res.status(500).json({
                message: error.message,
                error
            });
        });
};

// delete user by id
const deleteUserById = (req: Request, res: Response, next: NextFunction) => {
    logging.info(NAMESPACE, 'Deleting user by id.');

    let id = req.params.id;

    let checkQuery = 'SELECT id FROM users WHERE id = ?';
    let deleteQuery = 'DELETE FROM users WHERE id = ?';
    let values = [id];

    Connect()
        .then((connection) => {
            Query(connection, checkQuery, values)
                .then((results) => {
                    if (results instanceof Array && results.length === 0) {
                        return res.status(404).json({
                            message: 'User not found'
                        });
                    }

                    Query(connection, deleteQuery, values)
                        .then((deleteResults) => {
                            return res.status(200).json({ deleteResults });
                        })
                        .catch((error) => {
                            logging.error(NAMESPACE, error.message, error);

                            return res.status(500).json({
                                message: error.message,
                                error
                            });
                        })
                        .finally(() => {
                            connection.end();
                        });
                })
                .catch((error) => {
                    logging.error(NAMESPACE, error.message, error);

                    return res.status(500).json({
                        message: error.message,
                        error
                    });
                });
        })
        .catch((error) => {
            logging.error(NAMESPACE, error.message, error);

            return res.status(500).json({
                message: error.message,
                error
            });
        });
};

const getAllUsers = (req: Request, res: Response, next: NextFunction) => {
    logging.info(NAMESPACE, 'Getting all books.');

    let query = 'SELECT id, username FROM users';

    Connect().then((connection) => {
        Query<IUser[]>(connection, query)
            .then((results) => {
                return res.status(200).json({ results });
            })
            .catch((error) => {
                logging.error(NAMESPACE, error.message, error);

                return res.status(500).json({
                    message: error.message,
                    error
                });
            })
            .finally(() => {
                connection.end();
            });
    });
};

const getUserById = (req: Request, res: Response, next: NextFunction) => {
    logging.info(NAMESPACE, 'Getting user by id.');

    let id = req.params.id;

    let query = 'SELECT id, username FROM users WHERE id = ?';
    let values = [id];

    Connect().then((connection) => {
        Query<IUser[]>(connection, query, values)
            .then((results) => {
                if (results instanceof Array && results.length === 0) {
                    return res.status(404).json({
                        message: 'User not found'
                    });
                }

                return res.status(200).json({ results });
            })
            .catch((error) => {
                logging.error(NAMESPACE, error.message, error);

                return res.status(500).json({
                    message: error.message,
                    error
                });
            })
            .finally(() => {
                connection.end();
            });
    });
};

const getUserFavorites = (req: Request, res: Response, next: NextFunction) => {
    logging.info(NAMESPACE, 'Getting user favorites.');

    let query = 'SELECT favorites FROM users WHERE username = ?';

    Connect().then((connection) => {
        Query<IUser[]>(connection, query, [req.params.username])
            .then((results) => {
                if (results instanceof Array && results.length === 0) {
                    return res.status(404).json({
                        message: 'User not found'
                    });
                }
                let user = results as unknown as IUser[];
                return res.status(200).json({ favorites: user[0].favorites });
            })
            .catch((error) => {
                logging.error(NAMESPACE, error.message, error);

                return res.status(500).json({
                    message: error.message,
                    error
                });
            })
            .finally(() => {
                connection.end();
            });
    });
};

export default { getAllUsers, createUser, deleteAllUsers, deleteUserById, validateToken, login, getUserFavorites, whoAmI };
