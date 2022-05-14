import faker from '@faker-js/faker';
import { HttpStatus } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { CreateUserDto } from 'src/user/dto/create-user.dto';
import { UserService } from 'src/user/user.service';
import { UserDto } from '../../user/user.interface';
import { CredentialDto } from '../dto/credential.dto';
import { LoginDto } from '../dto/login.dto';
import { RegisterDto } from '../dto/register.dto';
import { ResponseDto } from '../dto/response.dto';
import { Auth } from '../entities/auth.entity';
import { AuthService } from './auth.service';
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
};

const MockUserService = {
  create: jest.fn(),
};

// const MockJwtService = {

// }

describe('AuthService', () => {
  let service: AuthService;
  let mockRegisterDto: RegisterDto;
  let mockLoginDto: LoginDto;
  let mockAuth: Auth;
  let mockCredential: CredentialDto;
  let mockUser: UserDto;

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
      ],
    }).compile();

    mockLoginDto = new LoginDto({
      email: faker.internet.email(),
      password: faker.internet.password(),
    });

    mockRegisterDto = new RegisterDto({
      email: faker.internet.email(),
      password: faker.internet.password(),
      firstname: faker.name.firstName(),
      lastname: faker.name.lastName(),
      displayName: faker.internet.userName(),
      imageUrl: faker.internet.url(),
    });

    mockCredential = new CredentialDto({
      accessToken: faker.lorem.word(),
      refreshToken: faker.lorem.word(),
      expiresIn: faker.datatype.number(30000),
    });

    mockAuth = new Auth({
      id: 1,
      email: faker.internet.email(),
      password: faker.internet.password(),
      isEmailVerified: false,
      userId: 1,
    });

    mockUser = {
      firstname: faker.name.firstName(),
      lastname: faker.name.lastName(),
      displayName: faker.internet.userName(),
      imageUrl: faker.internet.url(),
    };

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

      const user = await service.register(mockRegisterDto);

      expect(user).toStrictEqual(want);
      expect(MockUserService.create).toBeCalledWith(userDto);
      expect(MockUserService.create).toBeCalledTimes(1);
      expect(MockAuthRepository.save).toBeCalledWith(mockRegisterDto);
      expect(MockAuthRepository.save).toBeCalledTimes(1);
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

      const user = await service.register(mockRegisterDto);

      expect(user).toStrictEqual(want);
      expect(MockUserService.create).toBeCalledTimes(0);
      expect(MockAuthRepository.save).toBeCalledTimes(1);
      expect(MockAuthRepository.save).toBeCalledWith(mockRegisterDto);
    });
  });

  describe('login', () => {
    it('should return credentials if success', async () => {
      const want = new ResponseDto({
        statusCode: HttpStatus.OK,
        errors: null,
        data: mockCredential,
      });

      // const mockTokenDto = new CreateTokenDto({});

      MockTokenService.create.mockResolvedValue(want);
      MockAuthRepository.findOne.mockResolvedValue(mockAuth);

      const credentials = await service.login(mockLoginDto);

      expect(credentials).toStrictEqual(want);
      expect(MockAuthRepository.findOne).toBeCalledWith({ email: mockLoginDto.email });
      expect(MockAuthRepository.findOne).toBeCalledTimes(1);
      expect(MockTokenService.create).toBeCalledWith();
    });
  });
});
