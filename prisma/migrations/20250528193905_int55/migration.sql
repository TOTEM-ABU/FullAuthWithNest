/*
  Warnings:

  - You are about to drop the column `deviceInfo` on the `User` table. All the data in the column will be lost.
  - You are about to drop the column `otp` on the `User` table. All the data in the column will be lost.
  - You are about to drop the column `otpExpiresAt` on the `User` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "User" DROP COLUMN "deviceInfo",
DROP COLUMN "otp",
DROP COLUMN "otpExpiresAt";
