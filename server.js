const express = require('express');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const dotenv = require('dotenv');
const { MongoClient, ObjectId } = require('mongodb');
const MongoStore = require('connect-mongo'); 
const multer = require('multer');
const path = require('path');

dotenv.config(); // Load environment variables

const app = express();


// Global database variable
let db;

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static('public'));


// Connect to MongoDB
MongoClient.connect(process.env.MONGO_URI)
  .then(client => {
    console.log('MongoDB connected');
    db = client.db(); // Store the database connection
    app.locals.db = db; 
  })
  .catch(err => {
    console.error('MongoDB connection error:', err);
  });

// Configure session with MongoDB storage
const sessionStore = MongoStore.create({
  mongoUrl: process.env.MONGO_URI, // Use the correct syntax
  collectionName: 'sessions',
});

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: sessionStore, // Use sessionStore
  cookie: { secure: false, httpOnly: true }
}));

// Set up Express
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));

// Home page
app.get('/', async (req, res) => {
  let username = req.session.username || null;
  let isAdmin = req.session.role === 'admin'; // Check if the user is an admin

  try {
    const products = await db.collection('products').find().toArray();
    res.render('index', { username, isAdmin, products });
  } catch (err) {
    console.error('Error fetching products:', err);
    res.render('index', { username, isAdmin, products: [] });
  }
});


// Registration page
app.get('/register', (req, res) => {
  res.render('register', { error: null }); 
});

// Handle user registration
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  // Validate inputs
  if (!username || !email || !password) {
    return res.render('register', { error: 'All fields are required' });
  }

  if (password.length < 6) {
    return res.render('register', { error: 'Password must be at least 6 characters long' });
  }

  try {
    const existingUser = await db.collection('users').findOne({ email });
    if (existingUser) {
      return res.render('register', { error: 'Email is already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = { username, email, password: hashedPassword, role: 'user'};

    await db.collection('users').insertOne(newUser);
    res.redirect('/login');
  } catch (err) {
    console.error('Registration error:', err);
    res.render('register', { error: 'Error registering user' });
  }
});

// Login page
app.get('/login', (req, res) => {
  res.render('login', { error: null }); 
});


// Handle user login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  // Validate email and password
  if (!email || !password) {
    return res.render('login', { error: 'Email and password are required' });
  }

  try {
    const user = await db.collection('users').findOne({ email });

    // If the user is not found
    if (!user) {
      return res.render('login', { error: 'Unregistered email' });
    }

    // If account is locked
    if (user.failedAttempts >= 5) {
      if (user.lockedUntil && new Date() < user.lockedUntil) {
        return res.render('login', { error: 'Account locked. Please try again later.' });
      }

      // Reset failed attempts after lock period
      await db.collection('users').updateOne(
        { _id: new ObjectId(user._id) },
        { $set: { failedAttempts: 0, lockedUntil: null } }
      );
    }

    // Check the password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      // Increment failed attempts and lock account if necessary
      let updateData = { $inc: { failedAttempts: 1 } };

      if (user.failedAttempts >= 4) {
        // Lock account for 5 minutes after the 5th failed attempt
        updateData.$set = { lockedUntil: new Date(Date.now() + 5 * 60 * 1000) };
      }

      await db.collection('users').updateOne(
        { _id: new ObjectId(user._id) },
        updateData
      );

      return res.render('login', { error: 'Incorrect password' });
    }

    // Reset failed attempts on successful login
    await db.collection('users').updateOne(
      { _id: new ObjectId(user._id) },
      { $set: { failedAttempts: 0, lockedUntil: null } }
    );

    // Save session
    req.session.userId = user._id;
    req.session.username = user.username;
    req.session.role = user.role;
    res.redirect('/');
  } catch (err) {
    console.error('Login error:', err);
    res.render('login', { error: 'Error logging in' });
  }
});

// Logout user
app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

// multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = path.join(__dirname, 'uploads');
    console.log('Saving file to:', uploadPath); 
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    console.log('Saving file as:', file.originalname);
    cb(null, file.originalname);
  }
});


const upload = multer({ storage });

app.get('/edit-profile', async (req, res) => {
  if (req.session.userId) {
    const userId = req.session.userId;

    try {
      const user = await db.collection('users').findOne({ _id: new ObjectId(userId) });
      res.render('edit-profile', { 
        username: user.username, 
        email: user.email,  // Pass email to the view
        profilePicture: user.profilePicture || '',  // Pass profile picture if available
        error: null
      });
    } catch (err) {
      console.error('Error fetching user data:', err);
      res.status(500).send('Error fetching user data');
    }
  } else {
    res.redirect('/login');
  }
});


app.post('/edit-profile', upload.single('profilePicture'), async (req, res) => {
  const { username, email, currentPassword, newPassword } = req.body;
  const userId = req.session.userId;

  try {
    const user = await db.collection('users').findOne({ _id: new ObjectId(userId) });

    // Check if current password matches the one stored in the database
    const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password);

    if (!isCurrentPasswordValid) {
      return res.render('edit-profile', { 
        error: 'Incorrect password', 
        username: user.username, 
        email: user.email, 
        profilePicture: req.file ? '/uploads/' + req.file.filename : user.profilePicture 
      });
    }

    const profilePicture = req.file ? '/uploads/' + req.file.filename : user.profilePicture;

    // Prepare the update object
    const updateData = { 
      username: username, 
      email: email,
      profilePicture,
      error: null
    };

    // If the user wants to change the password
    if (newPassword) {
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      updateData.password = hashedPassword;
    }

    await db.collection('users').updateOne(
      { _id: new ObjectId(userId) },
      { $set: updateData }
    );

    req.session.username = username;
    res.redirect('/');
  } catch (err) {
    console.error('Error updating profile:', err);
    res.status(500).send('Error updating profile');
  }
});

// Start the server
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
  console.log(`http://localhost:${port}`); // Prints a link to the local site
});

const isAdmin = (req, res, next) => {
  if (req.session.role !== 'admin') {
    return res.status(403).send('Access denied');
  }
  next();
};

const isAuthenticated = (req, res, next) => {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  next();
};

app.get('/admin', isAuthenticated, isAdmin, async (req, res) => {
  res.render('admin', { error: null });
});

// Admin panel - view
app.get('/admin', async (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/login'); // Only logged-in users can access
  }

  res.render('admin', { error: null });
});

app.use(express.json()); // Для обработки JSON-запросов

// Getting data from collections
app.get('/admin/data', async (req, res) => {
    const { collection } = req.query;
    if (!collection || !['users', 'products'].includes(collection)) {
        return res.status(400).json({ error: 'Invalid collection' });
    }

    try {
        const data = await db.collection(collection).find().toArray();
        res.json(data);
    } catch (err) {
        console.error('Error fetching collection:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Adding new document
app.post('/admin/create/:collection', upload.single('image'), async (req, res) => {
  const { collection } = req.params;

  if (!['users', 'products'].includes(collection)) {
      return res.status(400).json({ error: 'Invalid collection' });
  }

  let newItem;
  if (collection === 'users') {
      const { username, email, password } = req.body;
      if (!username || !email || !password) {
          return res.status(400).json({ error: 'Missing required fields for user' });
      }

      try {
          const hashedPassword = await bcrypt.hash(password, 10);
          newItem = {
              username,
              email,
              password: hashedPassword,
              failedAttempts: 0,
              lockedUntil: null
          };
      } catch (err) {
          console.error('Error hashing password:', err);
          return res.status(500).json({ error: 'Internal server error' });
      }
  } else if (collection === 'products') {
      const { name, price, description, category } = req.body;
      if (!name || price == null || description === undefined || !category) {
          return res.status(400).json({ error: 'Missing required fields for product' });
      }

      newItem = {
          name,
          price: parseFloat(price),
          description,
          category,
          image: req.file ? `/uploads/${req.file.filename}` : null
      };
  }

  try {
      const result = await db.collection(collection).insertOne(newItem);
      res.json({ success: true, id: result.insertedId });
  } catch (err) {
      console.error('Error creating item:', err);
      res.status(500).json({ error: 'Internal server error' });
  }
});

// Find by ID
app.get('/admin/get/:collection/:id', async (req, res) => {
  const { collection, id } = req.params;
  if (!['users', 'products'].includes(collection)) {
      return res.status(400).json({ error: 'Invalid collection' });
  }

  try {
      const item = await db.collection(collection).findOne({ _id: new ObjectId(id) });

      if (!item) return res.status(404).json({ error: 'Item not found' });

      res.json([item]); // Оборачиваем в массив
  } catch (err) {
      console.error('Error fetching item:', err);
      res.status(500).json({ error: 'Internal server error' });
  }
});

// Find by other fields
app.get('/admin/find/:collection', async (req, res) => {
  const { collection } = req.params;
  const { field, value } = req.query;

  if (!collection || !['users', 'products'].includes(collection)) {
    return res.status(400).json({ error: 'Invalid collection' });
  }

  if (!field || !value) {
    return res.status(400).json({ error: 'Field and value are required' });
  }

  try {
    const query = { [field]: { $regex: value, $options: 'i' } };
    const data = await db.collection(collection).find(query).toArray();
    res.json(data);
  } catch (err) {
    console.error('Error searching collection:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update the document by ID
app.put('/admin/update/:collection/:id', async (req, res) => {
    const { collection, id } = req.params;
    if (!['users', 'products'].includes(collection)) {
        return res.status(400).json({ error: 'Invalid collection' });
    }

    try {
        let updateData = { ...req.body };

        if (collection === 'users' && updateData.password) {
            const saltRounds = 10;
            updateData.password = await bcrypt.hash(updateData.password, saltRounds);
        }

        const result = await db.collection(collection).updateOne(
            { _id: new ObjectId(id) },
            { $set: updateData }
        );

        if (result.modifiedCount === 0) {
            return res.status(404).json({ error: 'Item not found or no changes made' });
        }

        res.json({ success: true });
    } catch (err) {
        console.error('Error updating item:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});


// Delete document by ID
app.delete('/admin/delete/:collection/:id', async (req, res) => {
    const { collection, id } = req.params;
    if (!['users', 'products'].includes(collection)) {
        return res.status(400).json({ error: 'Invalid collection' });
    }

    try {
        const result = await db.collection(collection).deleteOne({ _id: new ObjectId(id) });
        if (result.deletedCount === 0) {
            return res.status(404).json({ error: 'Item not found' });
        }
        res.json({ success: true });
    } catch (err) {
        console.error('Error deleting item:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Filtering
app.get('/products', async (req, res) => {
  const { category, search, sort } = req.query;
  let filter = {};

  if (category) {
      filter.category = category;
  }

  if (search) {
      filter.name = { $regex: search, $options: 'i' }; 
  }

  let sortOptions = {};
  if (sort === 'asc') {
      sortOptions.price = 1; 
  } else if (sort === 'desc') {
      sortOptions.price = -1; 
  }

  try {
      const products = await db.collection('products')
          .find(filter)
          .sort(sortOptions)
          .toArray();
      res.json(products);
  } catch (err) {
      console.error('Error fetching products:', err);
      res.status(500).json({ error: 'Internal server error' });
  }
});

// Adding to cart 
app.post('/cart/add', isAuthenticated, async (req, res) => {
  const userId = req.session.userId;
  const { productId } = req.body;

  if (!userId) {
      return res.status(401).json({ message: 'You must be logged in to add items to the cart' });
  }

  try {
      const cartsCollection = db.collection('carts');

      let cart = await cartsCollection.findOne({ userId });

      if (!cart) {
          cart = { userId, items: [{ productId, quantity: 1 }] };
          await cartsCollection.insertOne(cart);
      } else {
          const existingItem = cart.items.find(item => item.productId === productId);

          if (existingItem) {
              await cartsCollection.updateOne(
                  { userId, 'items.productId': productId },
                  { $inc: { 'items.$.quantity': 1 } }
              );
          } else {
              await cartsCollection.updateOne(
                  { userId },
                  { $push: { items: { productId, quantity: 1 } } }
              );
          }
      }

      res.json({ message: 'Product added to cart' });
  } catch (error) {
      console.error('Error adding to cart:', error);
      res.status(500).json({ message: 'Server error' });
  }
});


// Open a cart
app.get('/cart', isAuthenticated, async (req, res) => {
    const userId = req.session.userId;

    try {
        const cartsCollection = db.collection('carts');
        const productsCollection = db.collection('products');

        let cart = await cartsCollection.findOne({ userId });

        if (!cart) {
            cart = { userId, items: [] };
            const result = await cartsCollection.insertOne(cart);
            cart._id = result.insertedId;
        }

        if (cart.items.length > 0) {
            const productIds = cart.items.map(item => new ObjectId(item.productId));

            const products = await productsCollection.find({ _id: { $in: productIds } }).toArray();

            cart.items = cart.items.map(item => {
                const product = products.find(p => p._id.toString() === item.productId.toString());
                if (product) {
                    return {
                        ...item,
                        productId: {
                            _id: product._id,
                            name: product.name || "Unknown Product",
                            price: product.price || 0,
                            imageUrl: product.imageUrl || ""
                        }
                    };
                } else {
                    return { ...item, productId: { name: "Unknown", price: 0, imageUrl: "" } };
                }
            });
        }
        res.render('cart', { cart });
    } catch (error) {
        console.error('Error fetching cart:', error);
        res.render('cart', { cart: { items: [] } });
    }
});


app.post('/cart/update', isAuthenticated, async (req, res) => {
  const userId = req.session.userId;
  const { productId, change } = req.body;

  try {
      const cartsCollection = db.collection('carts');

      await cartsCollection.updateOne(
          { userId, 'items.productId': productId },
          { $inc: { 'items.$.quantity': change } }
      );

      res.json({ message: 'Cart updated successfully' });
  } catch (error) {
      console.error('Error updating cart:', error);
      res.status(500).json({ message: 'Server error' });
  }
});

app.post('/cart/remove', isAuthenticated, async (req, res) => {
  const userId = req.session.userId;
  const { productId } = req.body;

  try {
      const cartsCollection = db.collection('carts');

      await cartsCollection.updateOne(
          { userId },
          { $pull: { items: { productId } } }
      );

      res.json({ message: 'Item removed from cart' });
  } catch (error) {
      console.error('Error removing item from cart:', error);
      res.status(500).json({ message: 'Server error' });
  }
});


app.post('/cart/checkout', async (req, res) => {
    try {
        const userId = req.session.userId;
        if (!userId) return res.status(401).json({ message: "Unauthorized" });

        const db = req.app.locals.db;
        const cartsCollection = db.collection('carts');
        const ordersCollection = db.collection('orders');
        const productsCollection = db.collection('products');

        const cart = await cartsCollection.findOne({ userId });

        if (!cart || cart.items.length === 0) {
            return res.status(400).json({ message: "Cart is empty!" });
        }

        console.log("🔍 Найденная корзина:", cart);

        const fullItems = await Promise.all(cart.items.map(async (item) => {
            try {
                const product = await productsCollection.findOne({ _id: new ObjectId(item.productId) });
                console.log("🔍 Найденный товар:", product);

                return {
                    name: product ? product.name : "Unknown",
                    price: product ? product.price : 0,
                    imageUrl: product ? product.imageUrl : "",
                    quantity: item.quantity
                };
            } catch (err) {
                console.error("❌ Ошибка поиска товара:", err);
                return {
                    name: "Unknown",
                    price: 0,
                    imageUrl: "",
                    quantity: item.quantity
                };
            }
        }));

        console.log("📦 Итоговые товары:", fullItems);

        const order = {
            userId,
            items: fullItems,
            totalPrice: fullItems.reduce((sum, item) => sum + item.price * item.quantity, 0),
            createdAt: new Date(),
        };

        console.log("📝 Создан заказ:", order);

        await ordersCollection.insertOne(order);
        await cartsCollection.deleteOne({ userId });

        res.json({ message: "Order placed successfully!" });

    } catch (error) {
        console.error("❌ Checkout Error:", error);
        res.status(500).json({ message: "Checkout failed.", error: error.message });
    }
});



app.get('/orders', isAuthenticated, async (req, res) => {
  const userId = req.session.userId;
  const db = req.app.locals.db;

  try {
      const ordersCollection = db.collection('orders');
      const orders = await ordersCollection.find({ userId }).toArray();
      res.render('orders', { orders });
  } catch (error) {
      console.error('Error fetching orders:', error);
      res.render('orders', { orders: [] });
  }
});
