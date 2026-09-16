import { z } from "zod";

export const loginSchema = z.object({
  email: z.string().email("Enter a valid work email"),
  password: z.string().min(6, "Password must be at least 6 characters"),
});

export const websiteSchema = z.object({
  url: z.string().trim().refine((value) => {
    try {
      if (/^(https?:\/\/)/i.test(value)) return Boolean(new URL(value).hostname);
      if (/^[a-f0-9:]+$/i.test(value) && value.includes(":")) return true;
      return value.split(".").length === 4 && value.split(".").every((part) => {
        const number = Number(part);
        return /^\d{1,3}$/.test(part) && number >= 0 && number <= 255;
      });
    } catch { return false; }
  }, "Enter a valid website URL or IP address"),
});

export const networkSchema = z.object({
  ipAddress: z.string().min(1, "Enter an IP address"),
  port: z.coerce.number().int().min(1, "Port must be between 1 and 65535").max(65535, "Port must be between 1 and 65535"),
});
