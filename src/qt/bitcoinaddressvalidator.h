// Copyright (c) 2011-2020 The DL0G Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_BITCOINADDRESSVALIDATOR_H
#define BITCOIN_QT_BITCOINADDRESSVALIDATOR_H

#include <QValidator>

/** Base58 entry widget validator, checks for valid characters and
 * removes some whitespace.
 */
class DL0GAddressEntryValidator : public QValidator
{
    Q_OBJECT

public:
    explicit DL0GAddressEntryValidator(QObject *parent);

    State validate(QString &input, int &pos) const override;
};

/** DL0G address widget validator, checks for a valid bitcoin address.
 */
class DL0GAddressCheckValidator : public QValidator
{
    Q_OBJECT

public:
    explicit DL0GAddressCheckValidator(QObject *parent);

    State validate(QString &input, int &pos) const override;
};

#endif // BITCOIN_QT_BITCOINADDRESSVALIDATOR_H
