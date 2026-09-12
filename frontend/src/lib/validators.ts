import { z } from "zod";

export const loginSchema = z.object({
  email: z.string().email("Enter a valid work email"),
  password: z.string().min(6, "Password must be at least 6 characters"),
});

export const websiteSchema = z.object({
  url: z.string().url("Enter a complete URL, including https://"),
});

export const networkSchema = z.object({
  ipAddress: z.string().min(1, "Enter an IP address"),
  port: z.coerce.number().int().min(1, "Port must be between 1 and 65535").max(65535, "Port must be between 1 and 65535"),
});
