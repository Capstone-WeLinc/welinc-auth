import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Patch,
  Post,
  Query,
  Req,
  Res,
  UploadedFile,
  UseGuards,
  UseInterceptors,
  ParseUUIDPipe,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import {
  InjectThrottlerStorage,
  type ThrottlerStorage,
} from '@nestjs/throttler';
import { SystemType } from '@prisma/client';
import type { Request, Response } from 'express';
import { AuthService, type OptionalCaller } from './auth.service';
import { CreateUserDto } from './dto/create-user.dto';
import { ListUsersQueryDto } from './dto/list-users.query.dto';
import { LookupUsersQueryDto } from './dto/lookup-users.query.dto';
import { SetUserStatusDto } from './dto/set-user-status.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { OtpResetPasswordDto } from './dto/otp-reset-password.dto';
import { VerifyOtpDto } from './dto/verify-otp.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { requestMeta } from './events/request-meta';
import {
  StartEmailChangeDto,
  VerifyEmailChangeDto,
} from './dto/email-verification.dto';
import { countCodeCall } from './codes/address-limit';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { OptionalJwtAuthGuard } from './guards/optional-jwt-auth.guard';
import { SystemAdmin } from './decorators/system-admin.decorator';
import type { Caller } from './guards/request-authenticator';

/**
 * The signed in admin, as the change record names them (spec 0009, AC-19, AC-20), plus the
 * system their request resolved to, which scopes every admin user endpoint (spec 0011, AC-26).
 */
type AdminRequest = Pick<Request, 'ip' | 'headers'> & {
  user: { sub: string; email: string; system: SystemType };
};
/** Spec 0011, AC-3: the admin's address and device go on every change event they make. */
const actorOf = (req: AdminRequest) => ({
  id: req.user.sub,
  email: req.user.email,
  system: req.user.system,
  meta: requestMeta(req),
});

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    @InjectThrottlerStorage() private readonly storage: ThrottlerStorage,
  ) {}

  // Public; an admin's token, when sent, records the reset as theirs and sees the send limits
  // (spec 0009, AC-13). 10 calls a minute per address on all three code routes (AC-6).
  @UseGuards(OptionalJwtAuthGuard)
  @Post('forgot-password')
  @HttpCode(HttpStatus.OK)
  async forgotPassword(
    @Body() dto: ForgotPasswordDto,
    @Req() req: Request & { user?: OptionalCaller },
    @Res({ passthrough: true }) res: Response,
  ) {
    await countCodeCall(this.storage, 'code-public', req, res);
    return this.authService.forgotPassword(dto.email, req.user ?? null);
  }

  @Post('verify-otp')
  @HttpCode(HttpStatus.OK)
  async verifyOtp(
    @Body() dto: VerifyOtpDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    await countCodeCall(this.storage, 'code-public', req, res);
    return this.authService.verifyOtp(dto.email, dto.otp);
  }

  @Post('reset-password')
  @HttpCode(HttpStatus.OK)
  async resetPasswordOtp(
    @Body() dto: OtpResetPasswordDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    await countCodeCall(this.storage, 'code-public', req, res);
    return this.authService.otpResetPassword(
      dto.email,
      dto.otp,
      dto.newPassword,
    );
  }

  // Spec 0004, AC-17: only the roles of the token's system (`aud`), whatever the query says
  @UseGuards(JwtAuthGuard)
  @Get('me')
  me(@Req() req: { user: { sub: string; system: SystemType } }) {
    return this.authService.getCurrentUser(req.user.sub, req.user.system);
  }

  // Admins of the token's system only. Backends read people through /auth/directory, so a
  // service token here gets 403 WRONG_TOKEN_USE (spec 0005, AC-9)
  @SystemAdmin()
  @Get('users')
  listUsers(@Query() query: ListUsersQueryDto, @Req() req: { user: Caller }) {
    return this.authService.listUsers(query, { system: req.user.system });
  }

  @SystemAdmin()
  @Get('users/lookup')
  lookupUsers(@Query() query: LookupUsersQueryDto, @Req() req: AdminRequest) {
    return this.authService.lookupUsers(query.q, actorOf(req));
  }

  @SystemAdmin()
  @Post('users')
  createUser(@Body() dto: CreateUserDto, @Req() req: AdminRequest) {
    return this.authService.createUser(dto, actorOf(req));
  }

  @SystemAdmin()
  @Patch('users/:id')
  updateUser(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: UpdateUserDto,
    @Req() req: AdminRequest,
  ) {
    return this.authService.updateUser(id, dto, actorOf(req));
  }

  @SystemAdmin()
  @Patch('users/:id/status')
  updateUserStatus(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: SetUserStatusDto,
    @Req() req: AdminRequest,
  ) {
    return this.authService.updateUserStatus(id, dto, actorOf(req));
  }

  @SystemAdmin()
  @Delete('users/:id')
  deleteUser(@Param('id', ParseUUIDPipe) id: string, @Req() req: AdminRequest) {
    return this.authService.deleteUser(id, actorOf(req));
  }

  @SystemAdmin()
  @Patch('users/:id/unlock')
  unlockUser(@Param('id', ParseUUIDPipe) id: string, @Req() req: AdminRequest) {
    return this.authService.unlockUser(id, actorOf(req));
  }

  @UseGuards(JwtAuthGuard)
  @Patch('profile')
  updateOwnProfile(
    @Req() req: { user: { sub: string } },
    @Body() dto: UpdateProfileDto,
  ) {
    return this.authService.updateOwnProfile(req.user.sub, dto);
  }

  // Spec 0009, AC-17 to AC-19: your own email changes only after the new address is confirmed
  @UseGuards(JwtAuthGuard)
  @Post('profile/email')
  @HttpCode(HttpStatus.OK)
  startEmailChange(
    @Req() req: { user: { sub: string } },
    @Body() dto: StartEmailChangeDto,
  ) {
    return this.authService.startEmailChange(req.user.sub, dto);
  }

  @UseGuards(JwtAuthGuard)
  @Post('profile/email/verify')
  @HttpCode(HttpStatus.OK)
  verifyEmailChange(
    @Req() req: { user: { sub: string } },
    @Body() dto: VerifyEmailChangeDto,
  ) {
    return this.authService.verifyEmailChange(req.user.sub, dto.code);
  }

  @UseGuards(JwtAuthGuard)
  @Delete('profile/email')
  @HttpCode(HttpStatus.NO_CONTENT)
  cancelEmailChange(@Req() req: { user: { sub: string } }) {
    return this.authService.cancelEmailChange(req.user.sub);
  }

  @UseGuards(JwtAuthGuard)
  @Patch('profile/password')
  changeOwnPassword(
    @Req() req: { user: { sub: string; sid: string } },
    @Body() dto: ChangePasswordDto,
  ) {
    return this.authService.changeOwnPassword(req.user.sub, dto, req.user.sid);
  }

  @UseGuards(JwtAuthGuard)
  @Post('profile/picture')
  @UseInterceptors(
    FileInterceptor('file', {
      limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB
      fileFilter: (_req, file, cb) => {
        const allowed = ['.png', '.jpg', '.jpeg', '.gif', '.webp'];
        const ext = file.originalname.toLowerCase().split('.').pop();
        if (!ext || !allowed.includes(`.${ext}`)) {
          return cb(new Error('Only image files are allowed'), false);
        }
        cb(null, true);
      },
    }),
  )
  uploadProfilePicture(
    @Req() req: { user: { sub: string } },
    @UploadedFile()
    file: {
      originalname: string;
      buffer: Buffer;
      size: number;
      mimetype: string;
    },
  ) {
    return this.authService.uploadProfilePicture(req.user.sub, file);
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile/summary')
  getProfileSummary(@Req() req: { user: { sub: string } }) {
    return this.authService.getProfileSummary(req.user.sub);
  }
}
