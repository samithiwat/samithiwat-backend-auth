import faker from '@faker-js/faker';
import { HttpStatus } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import * as bcrypt from 'bcrypt';
import { ServiceType } from 'src/common/enum/auth.enum';
import { TokenPayload } from 'src/common/types/auth';
import { CreateUserDto } from 'src/user/dto/create-user.dto';
import { UserService } from 'src/user/user.service';
import { UserDto } from '../../user/user.interface';
import { ChangePasswordDto } from '../dto/change-password.dto';
import { CreateTokenDto } from '../dto/create-token.dto';
import { CredentialDto } from '../dto/credential.dto';
import { LoginDto } from '../dto/login.dto';
import { RegisterDto } from '../dto/register.dto';
import { ResponseDto } from '../dto/response.dto';
import { UpdateTokenDto } from '../dto/update-token.dto';
import { Auth } from '../entities/auth.entity';
import { Token } from '../entities/token.entity';
import { AuthService } from './auth.service';
import { JwtService } from './jwt.service';
import { RefreshTokenService } from './refresh-token.service';
import { TokenService } from './token.service';

const MockAuthRepository = {
  save: jest.fn(),
  findOne: jest.fn(),
};

const MockTokenService = {
  create: jest.fn(),
  findOne: jest.fn(),
  update: jest.fn(),
  remove: jest.fn(),
  encode: jest.fn(),
  decode: jest.fn(),
};

const MockUserService = {
  create: jest.fn(),
};

const MockJwtService = {
  decode: jest.fn(),
  findFromPayload: jest.fn(),
  generate: jest.fn(),
  verify: jest.fn(),
};

const MockRefreshTokenService = {
  generate: jest.fn(),
  verify: jest.fn(),
  clear: jest.fn(),
};

const MockConfigService = {
  get: jest.fn(),
};

describe('AuthService', () => {
  let service: AuthService;
  let mockRegisterDto: RegisterDto;
  let mockAuth: Auth;
  let mockToken: Token;
  let mockLoginDto: LoginDto;
  let mockUser: UserDto;
  let mockChangePasswordDto: ChangePasswordDto;
  let mockCredentialDto: CredentialDto;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: getRepositoryToken(Auth),
          useValue: MockAuthRepository,
        },
        {
          provide: TokenService,
          useValue: MockTokenService,
        },
        {
          provide: UserService,
          useValue: MockUserService,
        },
        {
          provide: JwtService,
          useValue: MockJwtService,
        },
        {
          provide: RefreshTokenService,
          useValue: MockRefreshTokenService,
        },
        {
          provide: ConfigService,
          useValue: MockConfigService,
        },
      ],
    }).compile();

    mockRegisterDto = new RegisterDto({
      email: faker.internet.email(),
      password: faker.internet.password(),
      firstname: faker.name.firstName(),
      lastname: faker.name.lastName(),
      displayName: faker.internet.userName(),
      imageUrl: faker.internet.url(),
    });

    mockLoginDto = new LoginDto({
      email: faker.internet.email(),
      password: faker.internet.password(),
    });

    mockUser = {
      firstname: faker.name.firstName(),
      lastname: faker.name.lastName(),
      displayName: faker.internet.userName(),
      imageUrl: faker.internet.url(),
    };

    mockChangePasswordDto = new ChangePasswordDto({
      userId: 1,
      oldPassword: faker.internet.password(),
      newPassword: faker.internet.password(),
    });

    mockToken = new Token({
      id: 1,
      serviceType: ServiceType.APP,
      accessToken: faker.lorem.word(),
      refreshToken: faker.lorem.word(),
      expiresDate: faker.date.soon(),
      auth: new Auth({ id: 1 }),
    });

    mockAuth = new Auth({
      id: 1,
      email: faker.internet.email(),
      password: bcrypt.hashSync(faker.internet.password(), 10),
      isEmailVerified: true,
      userId: 1,
    });

    mockCredentialDto = new CredentialDto({
      accessToken: mockToken.accessToken,
      refreshToken: mockToken.refreshToken,
      expiresIn: 3600,
    });

    service = module.get<AuthService>(AuthService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('register', () => {
    it('should return user if success', async () => {
      const want = new ResponseDto({
        statusCode: HttpStatus.CREATED,
        errors: null,
        data: mockUser,
      });

      const userDto = new CreateUserDto({
        firstname: mockRegisterDto.firstname,
        lastname: mockRegisterDto.lastname,
        displayName: mockRegisterDto.displayName,
        imageUrl: mockRegisterDto.imageUrl,
      });

      MockUserService.create.mockResolvedValue(want);
      MockAuthRepository.save.mockResolvedValue(mockAuth);
      jest.spyOn(service, 'hashPassword').mockResolvedValue(mockRegisterDto.password);

      const user = await service.register(mockRegisterDto);

      expect(user).toStrictEqual(want);
      expect(MockUserService.create).toBeCalledWith(userDto);
      expect(MockAuthRepository.save).toBeCalledWith(mockRegisterDto);
      expect(service.hashPassword).toBeCalledWith(mockRegisterDto.password);
    });

    it('should throw error if email is already existed', async () => {
      const want = new ResponseDto({
        statusCode: HttpStatus.UNPROCESSABLE_ENTITY,
        errors: ['Email is already existed'],
        data: null,
      });

      const userRes = new ResponseDto({
        statusCode: HttpStatus.CREATED,
        errors: null,
        data: mockUser,
      });

      MockUserService.create.mockResolvedValue(userRes);
      MockAuthRepository.save.mockRejectedValue(new Error('Duplicated Email'));
      jest.spyOn(service, 'hashPassword').mockResolvedValue(mockRegisterDto.password);

      const user = await service.register(mockRegisterDto);

      expect(user).toStrictEqual(want);
      expect(MockUserService.create).toBeCalledTimes(0);
      expect(service.hashPassword).toBeCalledWith(mockRegisterDto.password);
      expect(MockAuthRepository.save).toBeCalledWith(mockRegisterDto);
    });
  });

  describe('storeToken', () => {
    it('should call update method and return token response if existed', async () => {
      const tokenRes = new ResponseDto({
        statusCode: HttpStatus.OK,
        errors: null,
        data: mockToken,
      });
      const want = mockToken;

      mockAuth.tokens = [mockToken];

      MockTokenService.update.mockResolvedValue(tokenRes);

      const res = await service.storeToken(mockAuth, mockToken);

      expect(res).toStrictEqual(want);
      expect(MockTokenService.update).toBeCalledWith(mockToken.id, mockToken as UpdateTokenDto);
      expect(MockTokenService.create).toBeCalledTimes(0);
    });

    it('should call create method and return token response if does not exist', async () => {
      const tokenRes = new ResponseDto({
        statusCode: HttpStatus.CREATED,
        errors: null,
        data: mockToken,
      });
      const want = mockToken;

      const mockTokenDto = new CreateTokenDto({});
      Object.assign(mockTokenDto, mockToken);
      mockTokenDto.auth = new Auth({ id: mockAuth.id });

      const mockAnotherToken = new Token({});
      Object.assign(mockAnotherToken, mockToken);
      mockAnotherToken.serviceType = ServiceType.GOOGLE;

      mockAuth.tokens = [mockAnotherToken];

      MockTokenService.create.mockResolvedValue(tokenRes);

      const res = await service.storeToken(mockAuth, mockToken);

      expect(res).toStrictEqual(want);
      expect(MockTokenService.update).toBeCalledTimes(0);
      expect(MockTokenService.create).toBeCalledWith(mockTokenDto);
    });
  });

  describe('login', () => {
    it('should return credentials if success', async () => {
      const mockTokenDto = new CreateTokenDto({
        serviceType: ServiceType.APP,
        accessToken: mockCredentialDto.accessToken,
        refreshToken: mockCredentialDto.refreshToken,
      });

      const want = new ResponseDto({
        statusCode: HttpStatus.OK,
        errors: null,
        data: mockCredentialDto,
      });

      MockAuthRepository.findOne.mockResolvedValue(mockAuth);
      jest.spyOn(service, 'isValidPassword').mockResolvedValue(true);
      MockJwtService.generate.mockResolvedValue(mockCredentialDto.accessToken);
      MockRefreshTokenService.generate.mockResolvedValue(mockCredentialDto.refreshToken);
      jest.spyOn(service, 'storeToken').mockResolvedValue(mockToken);
      MockConfigService.get.mockReturnValue('3600s');

      const credentials = await service.login(mockLoginDto);

      expect(credentials).toStrictEqual(want);
      expect(MockAuthRepository.findOne).toBeCalledWith(
        { email: mockLoginDto.email },
        { relations: ['tokens'] },
      );
      expect(service.isValidPassword).toBeCalledWith(mockLoginDto.password, mockAuth.password);
      expect(MockJwtService.generate).toBeCalledWith(mockAuth);
      expect(service.storeToken).toBeCalledWith(mockAuth, mockTokenDto);
      expect(MockConfigService.get).toBeCalledWith('jwt.tokenDuration');
    });

    it('should throw error if not verify email', async () => {
      const want = new ResponseDto({
        statusCode: HttpStatus.UNAUTHORIZED,
        errors: ['Email is not verified'],
        data: null,
      });

      mockAuth.isEmailVerified = false;
      MockAuthRepository.findOne.mockResolvedValue(mockAuth);
      jest.spyOn(service, 'isValidPassword').mockResolvedValue(true);

      const res = await service.login(mockLoginDto);

      expect(res).toStrictEqual(want);
      expect(MockAuthRepository.findOne).toBeCalledWith(
        { email: mockLoginDto.email },
        { relations: ['tokens'] },
      );
      expect(service.isValidPassword).toBeCalledWith(mockLoginDto.password, mockAuth.password);
      expect(MockJwtService.generate).toBeCalledTimes(0);
      expect(MockRefreshTokenService.generate).toBeCalledTimes(0);
      expect(MockTokenService.create).toBeCalledTimes(0);
      expect(MockConfigService.get).toBeCalledTimes(0);
    });

    it('should throw error if not found email', async () => {
      const want = new ResponseDto({
        statusCode: HttpStatus.UNAUTHORIZED,
        errors: ['Invalid email or password'],
        data: null,
      });

      mockAuth.password = bcrypt.hashSync(mockAuth.password, 10);

      MockAuthRepository.findOne.mockResolvedValue(undefined);
      jest.spyOn(service, 'isValidPassword');

      const credentials = await service.login(mockLoginDto);

      expect(credentials).toStrictEqual(want);
      expect(MockAuthRepository.findOne).toBeCalledWith(
        { email: mockLoginDto.email },
        { relations: ['tokens'] },
      );
      expect(service.isValidPassword).toBeCalledTimes(0);
      expect(MockJwtService.generate).toBeCalledTimes(0);
      expect(MockRefreshTokenService.generate).toBeCalledTimes(0);
      expect(MockTokenService.create).toBeCalledTimes(0);
      expect(MockConfigService.get).toBeCalledTimes(0);
    });

    it('should throw error if password not match', async () => {
      const want = new ResponseDto({
        statusCode: HttpStatus.UNAUTHORIZED,
        errors: ['Invalid email or password'],
        data: null,
      });

      MockAuthRepository.findOne.mockResolvedValue(mockAuth);
      jest.spyOn(service, 'isValidPassword').mockResolvedValue(false);

      const credentials = await service.login(mockLoginDto);

      expect(credentials).toStrictEqual(want);
      expect(MockAuthRepository.findOne).toBeCalledWith(
        { email: mockLoginDto.email },
        { relations: ['tokens'] },
      );
      expect(service.isValidPassword).toBeCalledWith(mockLoginDto.password, mockAuth.password);
      expect(MockJwtService.generate).toBeCalledTimes(0);
      expect(MockRefreshTokenService.generate).toBeCalledTimes(0);
      expect(MockTokenService.create).toBeCalledTimes(0);
      expect(MockConfigService.get).toBeCalledTimes(0);
    });
  });

  describe('logout', () => {
    it('should return nothing if success', async () => {
      const want = new ResponseDto({
        statusCode: HttpStatus.NO_CONTENT,
        errors: null,
        data: null,
      });

      mockAuth.tokens = [mockToken];

      jest.spyOn(service, 'validateToken').mockResolvedValue(mockAuth);
      MockTokenService.remove.mockResolvedValue(mockToken);

      const res = await service.logout(mockCredentialDto.accessToken);
      expect(res).toStrictEqual(want);
      expect(service.validateToken).toBeCalledWith(mockCredentialDto.accessToken);
      expect(MockTokenService.remove).toBeCalledWith(1);
      expect(MockTokenService.remove).toBeCalledTimes(1);
    });

    it('should throw error if invalid token', async () => {
      const want = new ResponseDto({
        statusCode: HttpStatus.UNAUTHORIZED,
        errors: ['Invalid token'],
        data: null,
      });

      jest.spyOn(service, 'validateToken').mockResolvedValue(null);

      const res = await service.logout(mockCredentialDto.accessToken);
      expect(res).toStrictEqual(want);
      expect(service.validateToken).toBeCalledWith(mockCredentialDto.accessToken);
      expect(MockTokenService.remove).toBeCalledTimes(0);
    });
  });

  describe('changePassword', () => {
    it('should return true if success', async () => {
      const want = new ResponseDto({
        statusCode: HttpStatus.OK,
        errors: null,
        data: true,
      });

      MockAuthRepository.findOne.mockResolvedValue(
        new Auth({
          id: mockAuth.id,
          email: mockAuth.email,
          password: mockAuth.password,
          isEmailVerified: mockAuth.isEmailVerified,
          userId: mockAuth.userId,
        }),
      );
      jest.spyOn(service, 'isValidPassword').mockResolvedValue(true);
      jest.spyOn(service, 'hashPassword').mockResolvedValue(mockAuth.password);
      MockAuthRepository.save.mockResolvedValue(mockAuth);

      const res = await service.changePassword(mockChangePasswordDto);
      expect(res).toStrictEqual(want);
      expect(MockAuthRepository.findOne).toBeCalledWith({ userId: mockChangePasswordDto.userId });
      expect(service.isValidPassword).toBeCalledWith(
        mockChangePasswordDto.oldPassword,
        mockAuth.password,
      );
      expect(service.hashPassword).toBeCalledWith(mockChangePasswordDto.newPassword);
      expect(MockAuthRepository.save).toBeCalledWith(mockAuth);
    });

    it('should throw error if userId not match', async () => {
      const want = new ResponseDto({
        statusCode: HttpStatus.UNAUTHORIZED,
        errors: ['Invalid userId or password'],
        data: false,
      });

      MockAuthRepository.findOne.mockResolvedValue(undefined);
      jest.spyOn(service, 'isValidPassword');
      jest.spyOn(service, 'hashPassword');

      const res = await service.changePassword(mockChangePasswordDto);
      expect(res).toStrictEqual(want);
      expect(MockAuthRepository.findOne).toBeCalledWith({ userId: mockChangePasswordDto.userId });
      expect(service.isValidPassword).toBeCalledTimes(0);
      expect(service.hashPassword).toBeCalledTimes(0);
      expect(MockAuthRepository.save).toBeCalledTimes(0);
    });

    it('should throw error if wrong password', async () => {
      const want = new ResponseDto({
        statusCode: HttpStatus.UNAUTHORIZED,
        errors: ['Invalid userId or password'],
        data: false,
      });

      MockAuthRepository.findOne.mockResolvedValue(mockAuth);
      jest.spyOn(service, 'isValidPassword').mockResolvedValue(false);
      jest.spyOn(service, 'hashPassword');

      const res = await service.changePassword(mockChangePasswordDto);
      expect(res).toStrictEqual(want);
      expect(MockAuthRepository.findOne).toBeCalledWith({ userId: mockChangePasswordDto.userId });
      expect(service.isValidPassword).toBeCalledWith(
        mockChangePasswordDto.oldPassword,
        mockAuth.password,
      );
      expect(service.hashPassword).toBeCalledTimes(0);
      expect(MockAuthRepository.save).toBeCalledTimes(0);
    });
  });

  describe('validateToken', () => {
    it('should return auth if success', async () => {
      const mockTokenPayload: TokenPayload = {
        iat: new Date().getTime(),
        exp: new Date().getTime() + 3600,
        id: mockAuth.userId,
      };

      const want = mockAuth;

      MockJwtService.decode.mockResolvedValue(mockTokenPayload);
      MockJwtService.findFromPayload.mockResolvedValue(mockAuth);

      const res = await service.validateToken(mockCredentialDto.accessToken);
      expect(res).toStrictEqual(want);
      expect(MockJwtService.decode).toBeCalledWith(mockCredentialDto.accessToken);
      expect(MockJwtService.findFromPayload).toBeCalledWith(mockTokenPayload);
    });

    it('should return null if invalid token (cannot decode)', async () => {
      const want = null;

      MockJwtService.decode.mockResolvedValue(undefined);

      const res = await service.validateToken(mockCredentialDto.accessToken);
      expect(res).toStrictEqual(want);
      expect(MockJwtService.decode).toBeCalledWith(mockCredentialDto.accessToken);
      expect(MockJwtService.findFromPayload).toBeCalledTimes(0);
    });

    it('should return undefined if invalid token (cannot find from database)', async () => {
      const mockTokenPayload: TokenPayload = {
        iat: new Date().getTime(),
        exp: new Date().getTime() + 3600,
        id: mockAuth.userId,
      };

      const want = undefined;

      MockJwtService.decode.mockResolvedValue(mockTokenPayload);
      MockJwtService.findFromPayload.mockResolvedValue(undefined);

      const res = await service.validateToken(mockCredentialDto.accessToken);
      expect(res).toStrictEqual(want);
      expect(MockJwtService.decode).toBeCalledWith(mockCredentialDto.accessToken);
      expect(MockJwtService.findFromPayload).toBeCalledWith(mockTokenPayload);
    });
  });

  describe('validate', () => {
    it('should return auth if success', async () => {
      const want = new ResponseDto({
        statusCode: HttpStatus.OK,
        errors: null,
        data: 1,
      });

      jest.spyOn(service, 'validateToken').mockResolvedValue(mockAuth);

      const res = await service.validate(mockCredentialDto.accessToken);

      expect(res).toStrictEqual(want);
      expect(service.validateToken).toBeCalledWith(mockCredentialDto.accessToken);
    });

    it('should throw error if invalid token', async () => {
      const want = new ResponseDto({
        statusCode: HttpStatus.UNAUTHORIZED,
        errors: ['Invalid token'],
        data: null,
      });

      jest.spyOn(service, 'validateToken').mockResolvedValue(null);

      const res = await service.validate(mockCredentialDto.accessToken);

      expect(res).toStrictEqual(want);
      expect(service.validateToken).toBeCalledWith(mockCredentialDto.accessToken);
    });
  });

  describe('refresh', () => {
    it('should return credential if success', async () => {
      const mockTokenRes = new ResponseDto({
        statusCode: HttpStatus.OK,
        errors: null,
        data: mockToken,
      });

      const want = new ResponseDto({
        statusCode: HttpStatus.OK,
        errors: null,
        data: mockCredentialDto,
      });

      MockTokenService.decode.mockResolvedValue(mockCredentialDto.refreshToken);
      MockRefreshTokenService.verify.mockResolvedValue(mockToken);
      MockRefreshTokenService.generate.mockResolvedValue(mockCredentialDto.refreshToken);
      MockJwtService.generate.mockResolvedValue(mockCredentialDto.accessToken);
      MockTokenService.update.mockResolvedValue(mockTokenRes);
      MockTokenService.encode.mockResolvedValue(mockCredentialDto.refreshToken);
      MockConfigService.get.mockReturnValue('3600s');

      const res = await service.refreshToken(mockCredentialDto.refreshToken);
      expect(res).toStrictEqual(want);
      expect(MockTokenService.decode).toBeCalledWith(mockCredentialDto.refreshToken);
      expect(MockRefreshTokenService.verify).toBeCalledWith(mockCredentialDto.refreshToken);
      expect(MockRefreshTokenService.generate).toBeCalledWith();
      expect(MockJwtService.generate).toBeCalledWith(mockToken.auth);
      expect(MockTokenService.update).toBeCalledWith(1, mockToken);
      expect(MockTokenService.encode).toBeCalledWith(mockCredentialDto.refreshToken);
    });

    it('should throw error if invalid refresh token (cannot decode)', async () => {
      const want = new ResponseDto({
        statusCode: HttpStatus.UNAUTHORIZED,
        errors: ['Invalid refresh token'],
        data: null,
      });

      MockTokenService.decode.mockRejectedValue(new Error('Cannot decrypt'));

      const res = await service.refreshToken(mockCredentialDto.refreshToken);
      expect(res).toStrictEqual(want);
      expect(MockTokenService.decode).toBeCalledWith(mockCredentialDto.refreshToken);
      expect(MockRefreshTokenService.verify).toBeCalledTimes(0);
      expect(MockRefreshTokenService.generate).toBeCalledTimes(0);
      expect(MockJwtService.generate).toBeCalledTimes(0);
      expect(MockTokenService.update).toBeCalledTimes(0);
      expect(MockTokenService.encode).toBeCalledTimes(0);
      expect(MockConfigService.get).toBeCalledTimes(0);
    });

    it('should throw error if invalid refresh token (cannot find from database)', async () => {
      const want = new ResponseDto({
        statusCode: HttpStatus.UNAUTHORIZED,
        errors: ['Invalid refresh token'],
        data: null,
      });

      MockTokenService.decode.mockResolvedValue(mockCredentialDto.refreshToken);
      MockRefreshTokenService.verify.mockResolvedValue(null);

      const res = await service.refreshToken(mockCredentialDto.refreshToken);
      expect(res).toStrictEqual(want);
      expect(MockTokenService.decode).toBeCalledWith(mockCredentialDto.refreshToken);
      expect(MockRefreshTokenService.verify).toBeCalledWith(mockCredentialDto.refreshToken);
      expect(MockRefreshTokenService.verify).toBeCalledTimes(1);
      expect(MockRefreshTokenService.generate).toBeCalledTimes(0);
      expect(MockJwtService.generate).toBeCalledTimes(0);
      expect(MockTokenService.update).toBeCalledTimes(0);
      expect(MockTokenService.encode).toBeCalledTimes(0);
      expect(MockConfigService.get).toBeCalledTimes(0);
    });
  });
});
