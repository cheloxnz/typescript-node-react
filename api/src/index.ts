import express, { Response, Request, NextFunction } from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import passport from 'passport';
import passportLocal from 'passport-local';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
import User from './User';
import { UserInterface, DatabaseUserInterface } from './interfaces/UserInterface';

const LocalStrategy = passportLocal.Strategy;

// connect to db
mongoose.connect(
	'mongodb+srv://DATABASE',
	{
		useCreateIndex: true,
		useNewUrlParser: true,
		useUnifiedTopology: true,
	},
	(err: Error) => {
		if (err) throw err;
		console.log('Connected MongoDB Atlas');
	}
);

// middlewares
const app = express();
app.use(express.json());
app.use(cors({ origin: 'http://localhost:3000', credentials: true }));
app.use(
	session({
		secret: 'secret',
		resave: true,
		saveUninitialized: true,
	})
);
app.use(cookieParser());
app.use(passport.initialize());
app.use(passport.session());

// passport
passport.use(
	new LocalStrategy((username: string, password: string, done) => {
		User.findOne({ username: username }, (err, user: any) => {
			if (err) throw err;
			if (!user) return done(null, false);
			// compare password, if true or no
			bcrypt.compare(password, user.password, (err, result: boolean) => {
				if (err) throw err;
				if (result === true) {
					return done(null, user);
				} else {
					return done(null, false);
				}
			});
		});
	})
);

// serializer user
passport.serializeUser((user: DatabaseUserInterface, cb) => {
	cb(null, user._id);
});

// deserializer user
passport.deserializeUser((id: string, cb) => {
	User.findOne({ _id: id }, (err, user: DatabaseUserInterface) => {
		const userInformation = {
			username: user.username,
			isAdmin: user.isAdmin,
		};
		cb(err, userInformation);
	});
});

// routes
app.post('/register', async (req: Request, res: Response) => {
	// user, password
	const { username, password } = req?.body;
	if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
		res.send('Improper values');
		return;
	}
	User.findOne({ username }, async (err: Error, doc: DatabaseUserInterface) => {
		if (err) throw err;
		if (doc) res.send('User already exists');
		// if there is no document, we create one
		if (!doc) {
			const hashPassword = await bcrypt.hash(password, 10);
			const newUser = new User({
				username,
				password: hashPassword,
			});
			await newUser.save();
			res.send('Success');
		}
	});
});

const isAdministratorMiddleware = (req: Request, res: Response, next: NextFunction) => {
	const { user }: any = req;
	if (user) {
		User.findOne({ username: user.username }, (err, doc: DatabaseUserInterface) => {
			if (err) throw err;
			if (doc?.isAdmin) {
				next();
			} else {
				res.send("Sorry, only admin's can perform this.");
			}
		});
	} else {
		res.send('Sorry, you arent logged in.');
	}
};

// local authentication method
app.post('/login', passport.authenticate('local'), (req, res) => {
	res.send('success');
});

app.get('/user', (req, res) => {
	res.send(req.user);
});

app.get('/logout', (req, res) => {
	req.logout();
	res.send('success');
});

app.post('/deleteuser', isAdministratorMiddleware, async (req, res) => {
	const { id } = req?.body;
	await User.findByIdAndDelete(id, (err) => {
		if (err) throw err;
	});
	res.send('success');
});

app.get('/getallusers', isAdministratorMiddleware, async (req, res) => {
	await User.find({}, (err, data: DatabaseUserInterface[]) => {
		if (err) throw err;
		const filteredUsers: UserInterface[] = [];
		data.forEach((item: DatabaseUserInterface) => {
			const userInformation = {
				id: item._id,
				username: item.username,
				isAdmin: item.isAdmin,
			};
			filteredUsers.push(userInformation);
		});
		res.send(filteredUsers);
	});
});

// server initializated
app.listen(4000, () => {
	console.log('Server is running at port 4000');
});
