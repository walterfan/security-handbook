# FastAPI with OAuth2 and JWT
## OAuth2
### 4 roles
* Resource Owner (RO): 资源所有者, 例如用户
* Resource Server (RS): 存储用户资源的服务器
* 客户端 client: 向资源拥有者发出授权请求的应用程序
* 授权服务器 Authorization Server: 授权服务器

### 4 flows
* Implicit flow
* Client credential flow
* Authorization code flow
* Resource password flow


### OAuth2PasswordBearer

作为基于密码的身份验证提供者

### OAuth2PasswordRequestForm
It is a class dependency that declares a form body with:

* The username.
* The password.
* An optional scope field as a big string, composed of strings separated by spaces.
* An optional grant_type.
* An optional client_id
* An optional client_secret


## Example

```python
from jose import JWTError, jwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def authenticate_user(db: Session, username: str, password: str):
    user = crud.get_user_by_username(db, username)
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

@router.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):

    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=401, detail="Incorrect username or password"
        )

    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

def verify_access_token(token):
    credentials_exception = HTTPException(
        status_code=401, detail="Could not validate credentials"
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            logger.warning(f"Invalid JWT token: {token}, {SECRET_KEY}, {ALGORITHM}")
            raise credentials_exception

    except Exception as e:
        logger.warning(f"Invalid JWT token: {e}")
        raise credentials_exception


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=60))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            logger.warning(f"Invalid JWT token: {token}, {SECRET_KEY}, {ALGORITHM}")
            raise credentials_exception
        token_data = schema.TokenData(username=username)
    except JWTError:
        raise credentials_exception

    user = crud.get_user_by_username(db, username=token_data.username)
    if user is None:
        logger.warning(f"Cannot get user by  {token_data.username}")
        raise credentials_exception
    return user
```