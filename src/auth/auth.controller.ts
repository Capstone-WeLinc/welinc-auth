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
  UploadedFile,
  UseGuards,
  UseInterceptors,
  ParseUUIDPipe,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { SystemType, UserRole } from '@prisma/client';
import { AuthService, type OptionalCaller } from './auth.service';
import { CreateUserDto } from './dto/create-user.dto';
import { ListUsersQueryDto } from './dto/list-users.query.dto';
import { LookupUsersQueryDto } from './dto/lookup-users.query.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { SetUserStatusDto } from './dto/set-user-status.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { OtpResetPasswordDto } from './dto/otp-reset-password.dto';
import { VerifyOtpDto } from './dto/verify-otp.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { ListChangesQueryDto } from './dto/list-changes.query.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { OptionalJwtAuthGuard } from './guards/optional-jwt-auth.guard';
import { RolesGuard } from './guards/roles.guard';
import { Roles } from './decorators/roles.decorator';
import { ServiceScope } from './decorators/service-scope.decorator';
import type { Caller } from './guards/request-authenticator';

/**
 * The signed in admin, as the change record names them (spec 0009, AC-19, AC-20), plus the
 * system their request resolved to, which scopes every admin user endpoint (spec 0011, AC-26).
 */
type AdminRequest = {
  user: { sub: string; email: string; system: SystemType };
};
const actorOf = (req: AdminRequest) => ({
  id: req.user.sub,
  email: req.user.email,
  system: req.user.system,
});

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  // Public; an admin's token, when sent, records the reset as theirs (spec 0009, AC-20)
  @UseGuards(OptionalJwtAuthGuard)
  @Post('forgot-password')
  @HttpCode(HttpStatus.OK)
  async forgotPassword(
    @Body() dto: ForgotPasswordDto,
    @Req() req: { user?: OptionalCaller },
  ) {
    return this.authService.forgotPassword(dto.email, req.user ?? null);
  }

  @Post('verify-otp')
  @HttpCode(HttpStatus.OK)
  async verifyOtp(@Body() dto: VerifyOtpDto) {
    return this.authService.verifyOtp(dto.email, dto.otp);
  }

  @Post('reset-password')
  @HttpCode(HttpStatus.OK)
  async resetPasswordOtp(@Body() dto: OtpResetPasswordDto) {
    return this.authService.otpResetPassword(
      dto.email,
      dto.otp,
      dto.newPassword,
    );
  }

  @UseGuards(JwtAuthGuard)
  @Get('me')
  me(@Req() req: { user: { sub: string } }) {
    return this.authService.getCurrentUser(req.user.sub);
  }

  // An admin of the token's system, or a backend's service token with directory.read, which
  // sees what an admin of its own system would, read only (spec 0002, AC-19)
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(UserRole.ADMIN)
  @ServiceScope('directory.read')
  @Get('users')
  listUsers(@Query() query: ListUsersQueryDto, @Req() req: { user: Caller }) {
    return this.authService.listUsers(query, { system: req.user.system });
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(UserRole.ADMIN)
  @Get('users/lookup')
  lookupUsers(@Query() query: LookupUsersQueryDto, @Req() req: AdminRequest) {
    return this.authService.lookupUsers(query.q, actorOf(req));
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(UserRole.ADMIN)
  @Post('users')
  createUser(@Body() dto: CreateUserDto, @Req() req: AdminRequest) {
    return this.authService.createUser(dto, actorOf(req));
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(UserRole.ADMIN)
  @Patch('users/:id')
  updateUser(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: UpdateUserDto,
    @Req() req: AdminRequest,
  ) {
    return this.authService.updateUser(id, dto, actorOf(req));
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(UserRole.ADMIN)
  @Patch('users/:id/status')
  updateUserStatus(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: SetUserStatusDto,
    @Req() req: AdminRequest,
  ) {
    return this.authService.updateUserStatus(id, dto, actorOf(req));
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(UserRole.ADMIN)
  @Delete('users/:id')
  deleteUser(@Param('id', ParseUUIDPipe) id: string, @Req() req: AdminRequest) {
    return this.authService.deleteUser(id, actorOf(req));
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(UserRole.ADMIN)
  @Get('users/:id/changes')
  listUserChanges(
    @Param('id', ParseUUIDPipe) id: string,
    @Query() query: ListChangesQueryDto,
    @Req() req: AdminRequest,
  ) {
    return this.authService.getUserChanges(id, query, actorOf(req));
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(UserRole.ADMIN)
  @Patch('users/:id/password')
  resetPassword(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: ResetPasswordDto,
    @Req() req: AdminRequest,
  ) {
    return this.authService.resetPassword(id, dto, actorOf(req));
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(UserRole.ADMIN)
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

  @UseGuards(JwtAuthGuard)
  @Patch('profile/password')
  changeOwnPassword(
    @Req() req: { user: { sub: string } },
    @Body() dto: ChangePasswordDto,
  ) {
    return this.authService.changeOwnPassword(req.user.sub, dto);
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
