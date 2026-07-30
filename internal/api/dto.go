package api

// Ответы Cabinet API бота Bedolaga. Поля повторяют Android-клиент; всё
// необязательное, потому что состав ответа зависит от версии бота.

type DeepLinkRequest struct {
	Token       string `json:"token"`
	BotUsername string `json:"bot_username"`
	ExpiresIn   int64  `json:"expires_in"`
}

type deepLinkPoll struct {
	Token string `json:"token"`
}

type emailLogin struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// User — то немногое из профиля, что нужно клиенту без кабинета.
type User struct {
	ID         int64  `json:"id"`
	TelegramID int64  `json:"telegram_id"`
	Email      string `json:"email"`
	Username   string `json:"username"`
	FirstName  string `json:"first_name"`
}

// Label — как показать пользователя в статусе.
func (u User) Label() string {
	switch {
	case u.Email != "":
		return u.Email
	case u.Username != "":
		return "@" + u.Username
	case u.TelegramID != 0:
		return "Telegram ID " + itoa(u.TelegramID)
	}
	return "—"
}

type AuthResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	User         *User  `json:"user"`
	Message      string `json:"message"`
}

type Subscription struct {
	ID              int64   `json:"id"`
	Status          string  `json:"status"`
	TariffName      string  `json:"tariff_name"`
	IsTrial         bool    `json:"is_trial"`
	EndDate         string  `json:"end_date"`
	DaysLeft        *int    `json:"days_left"`
	TrafficUsedGB   float64 `json:"traffic_used_gb"`
	TrafficLimitGB  float64 `json:"traffic_limit_gb"`
	DeviceLimit     *int    `json:"device_limit"`
	SubscriptionURL string  `json:"subscription_url"`
}

// Label — понятное имя подписки для списка.
func (s Subscription) Label() string {
	if s.TariffName != "" {
		return s.TariffName
	}
	if s.IsTrial {
		return "Пробная подписка"
	}
	return "Подписка #" + itoa(s.ID)
}

// Active — подписка действует. Панель отвечает по-разному в разных версиях.
func (s Subscription) Active() bool {
	switch s.Status {
	case "active", "trial", "активна":
		return true
	}
	return false
}

type subscriptionsResponse struct {
	Subscriptions []Subscription `json:"subscriptions"`
}

type connectionLink struct {
	SubscriptionURL string `json:"subscription_url"`
}

// UserInfo — заголовок subscription-userinfo из ответа Remnawave.
type UserInfo struct {
	Upload   int64 `json:"upload"`
	Download int64 `json:"download"`
	Total    int64 `json:"total"`
	Expire   int64 `json:"expire"`
}
