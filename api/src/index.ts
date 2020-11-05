import express, { Response, Request } from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import passport from 'passport';
import passportLocal from 'passport-local';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
import User from './User';
import { UserInterface } from './interfaces/UserInterface';

const LocalStrategy = passportLocal.Strategy;

// connect to db
mongoose.connect(
	'mongodb+srv://cheloxnz:cabj1212@cluster0.6ielk.mongodb.net/<dbname>?retryWrites=true&w=majority',
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
passport.serializeUser((user: any, cb) => {
	cb(null, user._id);
});

// deserializer user
passport.deserializeUser((id: string, cb) => {
	User.findOne({ _id: id }, (err, user: any) => {
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
		res.send('Inproper values');
		return;
	}
	User.findOne({ username }, async (err: Error, doc: UserInterface) => {
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

// local authentication method
app.post(
	'/login',
	passport.authenticate('local', (req, res) => {
		res.send('Successfully Authenticate');
	})
);

app.get('/user', (req, res) => {
	res.send(req.user);
});

// server initializated
app.listen(4000, () => {
	console.log('Server is running at port 4000');
});
