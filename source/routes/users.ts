import express from 'express';
import controller from '../controllers/users';
import extractJWT from '../middleware/extractJWT';
const router = express.Router();

// Routes
router.post('/login', controller.login); // Login route
router.get('/validate', extractJWT, controller.validateToken); // Validate token route
router.get('/getall', controller.getAllUsers); // Get all users route
router.post('/createone', controller.createUser); // Create user route
router.delete('/deleteall', controller.deleteAllUsers); // Delete all users route
router.delete('/deletebyid/:id', controller.deleteUserById); // Delete user by id route
router.get('/favorites/:username', extractJWT, controller.getUserFavorites); // Get user favorites route

export = router;
