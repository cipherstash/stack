module example.com/app

go 1.26

require (
	github.com/cipherstash/stack/languages/golang v0.0.0
	gorm.io/gorm v0.0.0
)

replace github.com/cipherstash/stack/languages/golang => ../../stubsdk

replace gorm.io/gorm => ../../stubgorm
