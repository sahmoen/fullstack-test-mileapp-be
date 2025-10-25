export const errorHandler = (err, req, res, next) => {
  console.error(err);

  const status = err.statusCode || 500;
  let message = err.message || "Internal Server Error";

  if (err.code === 11000) {
    const keys = Object.keys(err.keyValue);
    message = `Duplicate field value: ${keys.join(", ")}`;
  }

  if (err.name === "ValidationError") {
    message = Object.values(err.errors)
      .map((v) => v.message)
      .join(", ");
  }

  if (err.name === "JsonWebTokenError") message = "Invalid token";
  if (err.name === "TokenExpiredError") message = "Token expired";

  res.status(status).json({ status: "error", statusCode: status, message });
};
