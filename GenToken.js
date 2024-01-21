const jwt = require("jsonwebtoken");
const model = require("./model/model")


const authenticate = async (req, res, next) => {
    try {
      const loginToken = req.headers.authorization;
  
      if (!loginToken) {
        return res.status(401).json({ status: 401, message: "Unauthorized: Missing token" });
      }
  
      const decoded = jwt.verify(loginToken, process.env.SECRET_KEY);
  
      const user = await model.findById(decoded.id);
  
      if (!user) {
        return res.status(404).json({ status: 404, message: "User not found" });
      }
  
      req.rootUser = user;
      req.userId = user._id;
  
      next();
    } catch (error) {
      console.error("Authentication error:", error);
      res.status(401).json({ status: 401, message: "Unauthorized: Invalid token" });
    }
  };

module.exports =  authenticate ;